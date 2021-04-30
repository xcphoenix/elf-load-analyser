package form

// data structure used by graphviz
/*
Like:
	digraph structs {
		node[shape=record]
		linux_binprm [
			label="{
				linux_binprm |
				filename: char * |
				interp: char *   |
				fdpath: char *   |
				<mm> mm  |
				<vma> vma
			}"
		]

		mm_struct [
			label="{
				<mm> mm_struct |
				mmap: struct vma_area_struct * |
				stack_vm = 1 |
				rlim_stack = 0x0
			}"
		]

		linux_binprm:mm -> mm_struct:mm_struct
	}
*/
