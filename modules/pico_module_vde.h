#ifndef _PICO_MODULE_VDE_H
#define _PICO_MODULE_VDE_H

#ifndef IS_MODULE_VDE
# define _mod extern
#else
# define _mod
#endif
_mod struct pico_module pico_module_vde;
#undef _mod

#endif
