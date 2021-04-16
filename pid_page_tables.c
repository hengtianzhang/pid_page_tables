#include <linux/debugfs.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/module.h>

#include <asm/fixmap.h>
#include <asm/kasan.h>
#include <asm/memory.h>
#include <asm/pgtable.h>
#include <asm/pgtable-hwdef.h>
#include <asm/ptdump.h>

static struct dentry *pid_page_tables_file;
struct mm_struct mm;

static unsigned long start_code;
static unsigned long end_code;
static unsigned long start_data;
static unsigned long end_data;
static unsigned long start_brk;
static unsigned long end_brk;
static unsigned long mmap_end;
static unsigned long mmap_base;
static unsigned long misc_start;
static unsigned long misc_end;

static unsigned long stack_top;
static unsigned long arg_start;
static unsigned long arg_end;
static unsigned long env_start;
static unsigned long env_end;


/* Kernel space */
static const struct addr_marker address_markers[] = {
#ifdef CONFIG_KASAN
	{ KASAN_SHADOW_START,		"Kasan shadow start" },
	{ KASAN_SHADOW_END,		"Kasan shadow end" },
#endif
	{ MODULES_VADDR,		"Modules start" },
	{ MODULES_END,			"Modules end" },
	{ VMALLOC_START,		"vmalloc() Area" },
	{ VMALLOC_END,			"vmalloc() End" },
	{ FIXADDR_START,		"Fixmap start" },
	{ FIXADDR_TOP,			"Fixmap end" },
	{ PCI_IO_START,			"PCI I/O start" },
	{ PCI_IO_END,			"PCI I/O end" },
#ifdef CONFIG_SPARSEMEM_VMEMMAP
	{ VMEMMAP_START,		"vmemmap start" },
	{ VMEMMAP_START + VMEMMAP_SIZE,	"vmemmap end" },
#endif
	{ PAGE_OFFSET,			"Linear Mapping" },
	{ -1,				NULL },
};

#define pt_dump_seq_printf(m, fmt, args...)	\
({						\
	if (m)					\
		seq_printf(m, fmt, ##args);	\
})

#define pt_dump_seq_puts(m, fmt)	\
({					\
	if (m)				\
		seq_printf(m, fmt);	\
})

/*
 * The page dumper groups page table entries of the same type into a single
 * description. It uses pg_state to track the range information while
 * iterating over the pte entries. When the continuity is broken it then
 * dumps out a description of the range.
 */
struct pg_state {
	struct seq_file *seq;
	const struct addr_marker *marker;
	unsigned long start_address;
	unsigned level;
	u64 current_prot;
	bool check_wx;
	unsigned long wx_pages;
	unsigned long uxn_pages;
};

struct prot_bits {
	u64		mask;
	u64		val;
	const char	*set;
	const char	*clear;
};

static const struct prot_bits pte_bits[] = {
	{
		.mask	= PTE_VALID,
		.val	= PTE_VALID,
		.set	= " ",
		.clear	= "F",
	}, {
		.mask	= PTE_USER,
		.val	= PTE_USER,
		.set	= "USR",
		.clear	= "   ",
	}, {
		.mask	= PTE_RDONLY,
		.val	= PTE_RDONLY,
		.set	= "ro",
		.clear	= "RW",
	}, {
		.mask	= PTE_PXN,
		.val	= PTE_PXN,
		.set	= "NX",
		.clear	= "x ",
	}, {
		.mask	= PTE_SHARED,
		.val	= PTE_SHARED,
		.set	= "SHD",
		.clear	= "   ",
	}, {
		.mask	= PTE_AF,
		.val	= PTE_AF,
		.set	= "AF",
		.clear	= "  ",
	}, {
		.mask	= PTE_NG,
		.val	= PTE_NG,
		.set	= "NG",
		.clear	= "  ",
	}, {
		.mask	= PTE_CONT,
		.val	= PTE_CONT,
		.set	= "CON",
		.clear	= "   ",
	}, {
		.mask	= PTE_TABLE_BIT,
		.val	= PTE_TABLE_BIT,
		.set	= "   ",
		.clear	= "BLK",
	}, {
		.mask	= PTE_UXN,
		.val	= PTE_UXN,
		.set	= "UXN",
	}, {
		.mask	= PTE_ATTRINDX_MASK,
		.val	= PTE_ATTRINDX(MT_DEVICE_nGnRnE),
		.set	= "DEVICE/nGnRnE",
	}, {
		.mask	= PTE_ATTRINDX_MASK,
		.val	= PTE_ATTRINDX(MT_DEVICE_nGnRE),
		.set	= "DEVICE/nGnRE",
	}, {
		.mask	= PTE_ATTRINDX_MASK,
		.val	= PTE_ATTRINDX(MT_DEVICE_GRE),
		.set	= "DEVICE/GRE",
	}, {
		.mask	= PTE_ATTRINDX_MASK,
		.val	= PTE_ATTRINDX(MT_NORMAL_NC),
		.set	= "MEM/NORMAL-NC",
	}, {
		.mask	= PTE_ATTRINDX_MASK,
		.val	= PTE_ATTRINDX(MT_NORMAL),
		.set	= "MEM/NORMAL",
	}
};

struct pg_level {
	const struct prot_bits *bits;
	const char *name;
	size_t num;
	u64 mask;
};

static struct pg_level pg_level[] = {
	{
	}, { /* pgd */
		.name	= "PGD",
		.bits	= pte_bits,
		.num	= ARRAY_SIZE(pte_bits),
	}, { /* pud */
		.name	= (CONFIG_PGTABLE_LEVELS > 3) ? "PUD" : "PGD",
		.bits	= pte_bits,
		.num	= ARRAY_SIZE(pte_bits),
	}, { /* pmd */
		.name	= (CONFIG_PGTABLE_LEVELS > 2) ? "PMD" : "PGD",
		.bits	= pte_bits,
		.num	= ARRAY_SIZE(pte_bits),
	}, { /* pte */
		.name	= "PTE",
		.bits	= pte_bits,
		.num	= ARRAY_SIZE(pte_bits),
	},
};

static void dump_prot(struct pg_state *st, const struct prot_bits *bits,
			size_t num)
{
	unsigned i;

	for (i = 0; i < num; i++, bits++) {
		const char *s;

		if ((st->current_prot & bits->mask) == bits->val)
			s = bits->set;
		else
			s = bits->clear;

		if (s)
			pt_dump_seq_printf(st->seq, " %s", s);
	}
}

static void note_prot_uxn(struct pg_state *st, unsigned long addr)
{
	if (!st->check_wx)
		return;

	if ((st->current_prot & PTE_UXN) == PTE_UXN)
		return;

	WARN_ONCE(1, "arm64/mm: Found non-UXN mapping at address %p/%pS\n",
		  (void *)st->start_address, (void *)st->start_address);

	st->uxn_pages += (addr - st->start_address) / PAGE_SIZE;
}

static void note_prot_wx(struct pg_state *st, unsigned long addr)
{
	if (!st->check_wx)
		return;
	if ((st->current_prot & PTE_RDONLY) == PTE_RDONLY)
		return;
	if ((st->current_prot & PTE_PXN) == PTE_PXN)
		return;

	WARN_ONCE(1, "arm64/mm: Found insecure W+X mapping at address %p/%pS\n",
		  (void *)st->start_address, (void *)st->start_address);

	st->wx_pages += (addr - st->start_address) / PAGE_SIZE;
}

static void note_page(struct pg_state *st, unsigned long addr, unsigned level,
				u64 val)
{
	static const char units[] = "KMGTPE";
	u64 prot = val & pg_level[level].mask;

	if (!st->level) {
		st->level = level;
		st->current_prot = prot;
		st->start_address = addr;
		pt_dump_seq_printf(st->seq, "---[ %s ]---\n", st->marker->name);
	} else if (prot != st->current_prot || level != st->level ||
		   addr >= st->marker[1].start_address) {
		const char *unit = units;
		unsigned long delta;

		if (st->current_prot) {
			note_prot_uxn(st, addr);
			note_prot_wx(st, addr);
			pt_dump_seq_printf(st->seq, "0x%016lx-0x%016lx   ",
				   st->start_address, addr);

			delta = (addr - st->start_address) >> 10;
			while (!(delta & 1023) && unit[1]) {
				delta >>= 10;
				unit++;
			}
			pt_dump_seq_printf(st->seq, "%9lu%c %s", delta, *unit,
				   pg_level[st->level].name);
			if (pg_level[st->level].bits)
				dump_prot(st, pg_level[st->level].bits,
					  pg_level[st->level].num);
			pt_dump_seq_puts(st->seq, "\n");
		}

		if (addr >= st->marker[1].start_address) {
			st->marker++;
			pt_dump_seq_printf(st->seq, "---[ %s ]---\n", st->marker->name);
		}

		st->start_address = addr;
		st->current_prot = prot;
		st->level = level;
	}

	if (addr >= st->marker[1].start_address) {
		st->marker++;
		pt_dump_seq_printf(st->seq, "---[ %s ]---\n", st->marker->name);
	}
}

static void walk_pte(struct pg_state *st, pmd_t *pmdp, unsigned long start)
{
	pte_t *ptep = pte_offset_kernel(pmdp, 0UL);
	unsigned long addr;
	unsigned i;

	for (i = 0; i < PTRS_PER_PTE; i++, ptep++) {
		addr = start + i * PAGE_SIZE;
		note_page(st, addr, 4, READ_ONCE(pte_val(*ptep)));
	}
}

static void walk_pmd(struct pg_state *st, pud_t *pudp, unsigned long start)
{
	pmd_t *pmdp = pmd_offset(pudp, 0UL);
	unsigned long addr;
	unsigned i;

	for (i = 0; i < PTRS_PER_PMD; i++, pmdp++) {
		pmd_t pmd = READ_ONCE(*pmdp);

		addr = start + i * PMD_SIZE;
		if (pmd_none(pmd) || pmd_sect(pmd)) {
			note_page(st, addr, 3, pmd_val(pmd));
		} else {
			BUG_ON(pmd_bad(pmd));
			walk_pte(st, pmdp, addr);
		}
	}
}

static void walk_pud(struct pg_state *st, pgd_t *pgdp, unsigned long start)
{
	pud_t *pudp = pud_offset(pgdp, 0UL);
	unsigned long addr;
	unsigned i;

	for (i = 0; i < PTRS_PER_PUD; i++, pudp++) {
		pud_t pud = READ_ONCE(*pudp);

		addr = start + i * PUD_SIZE;
		if (pud_none(pud) || pud_sect(pud)) {
			note_page(st, addr, 2, pud_val(pud));
		} else {
			BUG_ON(pud_bad(pud));
			walk_pmd(st, pudp, addr);
		}
	}
}

static void walk_pgd(struct pg_state *st, struct mm_struct *mm,
		     unsigned long start)
{
	pgd_t *pgdp = pgd_offset(mm, 0UL);
	unsigned i;
	unsigned long addr;

	for (i = 0; i < PTRS_PER_PGD; i++, pgdp++) {
		pgd_t pgd = READ_ONCE(*pgdp);

		addr = start + i * PGDIR_SIZE;
		if (pgd_none(pgd)) {
			note_page(st, addr, 1, pgd_val(pgd));
		} else {
			BUG_ON(pgd_bad(pgd));
			walk_pud(st, pgdp, addr);
		}
	}
}

void ptdump_walk_pgd(struct seq_file *m, struct ptdump_info *info)
{
	struct pg_state st = {
		.seq = m,
		.marker = info->markers,
	};

	walk_pgd(&st, info->mm, info->base_addr);

	note_page(&st, 0, 0, 0);
}

static int ptdump_show(struct seq_file *m, void *v)
{
	struct ptdump_info *info = m->private;
	ptdump_walk_pgd(m, info);
	return 0;
}

static void ptdump_initialize(void)
{
	unsigned i, j;

	for (i = 0; i < ARRAY_SIZE(pg_level); i++)
		if (pg_level[i].bits)
			for (j = 0; j < pg_level[i].num; j++)
				pg_level[i].mask |= pg_level[i].bits[j].mask;
}

static struct ptdump_info kernel_ptdump_info = {
	.markers	= address_markers,
	.base_addr	= VA_START,
};

static int pid_page_tables_open(struct inode *inode, struct file *file)
{
	return single_open(file, &ptdump_show, inode->i_private);
}

ssize_t pid_page_tables_write(struct file *f, const char __user *b, size_t s, loff_t *o)
{
	void *buffer;
	unsigned long pid;
	struct pid *kpid;
	struct task_struct *ts;

	buffer = kzalloc(s, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	if (copy_from_user(buffer, b, s))
		return -EFAULT;

	printk("Input: %s\n", (char *)buffer);
	if (kstrtoul(buffer, 0, &pid))
		return -EINVAL;
	
	printk("str to ul 0x%lx\n", pid);

	kpid = find_get_pid(pid);
	ts = get_pid_task(kpid, PIDTYPE_PID);
	if (ts) {
		printk("aaaaaa task comm %s\n", ts->comm);
		printk("aaaaaa task mm 0x%lx\n", ts->mm);
		printk("aaaaaa task mm 0x%lx\n", ts->active_mm);
		if (ts->mm) {
			struct vm_area_struct *tmp = ts->mm->mmap->vm_prev;
			struct vm_area_struct *vma = ts->mm->mmap;
			printk("pgd 0x%lx\n", ts->mm->pgd);
			mm.pgd = ts->mm->pgd;
			kernel_ptdump_info.base_addr = 0;
			printk("aaaa text code 0x%lx - 0x%lx\n", ts->mm->start_code, ts->mm->end_code);
			printk("aaaa data 0x%lx - 0x%lx\n", ts->mm->start_data, ts->mm->end_data);
			printk("aaaa brk 0x%lx - 0x%lx\n", ts->mm->start_brk, ts->mm->brk);
			printk("aaaa stack 0x%lx\n", ts->mm->start_stack);
			printk("aaaa arg_start 0x%lx - 0x%lx\n", ts->mm->arg_start, ts->mm->arg_end);
			printk("aaaa env_start 0x%lx - 0x%lx\n", ts->mm->env_start, ts->mm->env_end);
			printk("aaaa mmap_base 0x%lx - 0x%lx\n", ts->mm->mmap_base, ts->mm->highest_vm_end);
			while (vma) {
				printk("aaaa vma 0x%lx - 0x%lx\n", vma->vm_start, vma->vm_end);
				vma = vma->vm_next;
			}
			while (tmp) {
				printk("tmp vma 0x%lx - 0x%lx\n", tmp->vm_start, tmp->vm_end);
				tmp = tmp->vm_prev;
			}
			
		}
	}


	kfree(buffer);

	return s;
}

static const struct file_operations pid_page_tables_fops = {
	.owner = THIS_MODULE,
	.open = pid_page_tables_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = pid_page_tables_write,
};

static int __init pid_page_tables_init(void)
{
	unsigned long ttbr1 = read_sysreg(ttbr1_el1);
	mm.pgd = (pgd_t *)phys_to_virt(__phys_to_pgd_val(ttbr1));
	kernel_ptdump_info.mm = &mm;

	ptdump_initialize();
	pid_page_tables_file = debugfs_create_file("pid_page_tables", 0444, NULL,
	&kernel_ptdump_info, &pid_page_tables_fops);

	return 0;
}

static void __exit pid_page_tables_exit(void)
{
	if (pid_page_tables_file)
		debugfs_remove(pid_page_tables_file);
}

module_init(pid_page_tables_init);
module_exit(pid_page_tables_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
