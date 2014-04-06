/*
 *    xnippet.c: extract snippets of code from a program and run them
 *               output it, and debug it.
 *
 *    Copyright (c) 2011  Gonzalo J. Carracedo (BatchDrake)
 *              (c) 2011  Painsec
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
 
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <setjmp.h>
#include <signal.h>
#include <getopt.h>
#include <ctype.h>
#include <dlfcn.h>

/* TODO: reserve data pages */

#define PAGE_SIZE 4096

#define _JOIN(a, b) a ## b
#define JOIN(a, b) _JOIN(a, b)

#define PTR_LIST(type, name)                         \
  type ** name ## _list;                             \
  int     name ## _count;
  
#define PTR_LIST_APPEND(name, ptr)  \
  ptr_list_append ((void ***) &JOIN (name, _list),   \
                   &JOIN (name, _count), ptr)
                   
typedef unsigned int busword_t;
typedef unsigned int reg_t;

#define TRAMPOLINE_SIZE 6
#define SIGHANDLER_STACK_SIZE SIGSTKSZ

#define PAGE_OFFSET_MASK (PAGE_SIZE - 1)
#define NOP_BYTE 0x90

#define MMAP_EXTRA_BYTES 0x16 /* Clening up the stack */
#define error(fmt, arg...) fprintf (stderr, "xnippet error: " fmt, ##arg)
#define warning(fmt, arg...) fprintf (stderr, "xnippet warning: " fmt, ##arg)
#define notice(fmt, arg...) fprintf (stderr, "xnippet notice: " fmt, ##arg)
#define debug(fmt, arg...) \
do { \
  if (verbose) \
    fprintf (stderr, "xnippet notice: " fmt, ##arg); \
   } while (0);

#define CALL_TYPE_STDCALL 0
#define CALL_TYPE_PASCAL  1

#define X86_REG_EAX 7
#define X86_REG_ECX 6
#define X86_REG_EDX 5
#define X86_REG_EBX 4
#define X86_REG_ESP 3
#define X86_REG_EBP 2
#define X86_REG_ESI 1
#define X86_REG_EDI 0

/* Everybody loves executable stacks */
#define DEFAULT_STACK_PROT PROT_READ | PROT_EXEC | PROT_WRITE
#define DEFAULT_STACK_SIZE 16384 /* 16 KiB stack */
 
 
const int failure_sigs[] = 
                     {SIGTSTP, SIGTTIN, SIGTTOU, SIGTRAP,
                      SIGSYS,  SIGBUS, SIGSEGV, SIGILL,
                      SIGFPE,  SIGPIPE, SIGSTKFLT, SIGXCPU,
                      SIGXFSZ, SIGHUP, SIGINT};


struct snippet_context_info
{
  void  *stack_top;
  size_t stack_size;
  int    stack_prot;
   
/* -----8<----------------- MACHINE DEPENDANT SECTION START ------------- */
  reg_t registers[8];
/* -----8<----------------- MACHINE DEPENDANT SECTION STOP -------------- */
};

struct snippet_call_info
{
  int    call_type;
  int    arg_count;
  void **arg_list;
  int    retval;
  void  *snippet;
  size_t len;
  
  struct snippet_context_info context;
};

struct lib_info
{
  char *name;
  void *handle;
};

struct trampoline
{
  void *from;
  void *to;
};

PTR_LIST (struct trampoline, trampolines);
PTR_LIST (struct lib_info, libs);

sigjmp_buf env;
siginfo_t siginfo;

void **trampoline_page;
int    trampoline_page_count;

void  *sighandler_stack_top;
void *base;

int print_siginfo;
int print_regdump;
int print_retval;
int mark_output;
int do_trap;
int verbose;

void*
xmalloc (size_t size)
{
  void* m;
  
  m = malloc (size);

  if (m == NULL)
    abort ();
  
  return m;
}

/* Wrapper para strdup */
char *
xstrdup (const char *str)
{
  char *ret;

  if (str != NULL)
  {
    ret = xmalloc (strlen (str) + 1);
    strcpy (ret, str);
  }
  else
    ret = NULL;
  
  return ret;
}


/* Wrapper para realloc */
void*
xrealloc (void* ptr, size_t new_size)
{
  void* m;
  
  m = realloc (ptr, new_size);
  
  if (m == NULL)
    abort ();

  return m;
}

void
ptr_list_append (void ***list, int *count, void *new)
{
  int i;
  
  for (i = 0; i < *count; i++)
    if ((*list)[i] == NULL)
      break;
      
  if (i == *count)
    *list = xrealloc (*list, ++*count * sizeof (void *));
    
  (*list)[i] = new;
}

static inline void
__x86_setup_trampoline (char *from, void *to)
{
  from[0] = 0x68; /* push dword */
  memcpy (from + 1, &to, 4); /* Address */
  from[5] = 0xc3; /* ret */
}

void *
trampoline_allocate_page (void *address)
{
  void *tramp;
  
  if (address == (void *) ((busword_t) base & ~PAGE_OFFSET_MASK))
    return address; /* We already have this */
    
  tramp = mmap (address, 
                PAGE_SIZE, 
                PROT_READ | PROT_EXEC | PROT_WRITE, 
                MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, 0, 0);
                
  if (tramp != (void *) -1)
    memset (tramp, NOP_BYTE, PAGE_SIZE);
  else
    error ("mmap failed: %s\n", strerror (errno));
  return tramp;
}

void
mark (void)
{
  int i;
  
  printf ("----------8<");
  
  for (i = 5; i < 40; i++)
    putchar ('-');
    
  putchar (10);
}


int
trampoline_register (void *from, void *to)
{
  int i;
  busword_t offset;
  void *page;

  
  page = (void *) ((busword_t) from & ~PAGE_OFFSET_MASK);
  offset = (busword_t) from & ~PAGE_OFFSET_MASK;
  
  for (i = 0; i < trampoline_page_count; i++)
    if (page == trampoline_page[i])
      break;
  
  if (i == trampoline_page_count)
  {
    if (trampoline_allocate_page (page) == (void *) -1)
      return -1;

    trampoline_page = xrealloc (trampoline_page, ++trampoline_page_count * sizeof (void *));
    trampoline_page[i] = page;
    
    /* What if trampoline code lies between two pages? We have to consider
       this highly unlikely posibility */
       
    if (PAGE_SIZE - offset < TRAMPOLINE_SIZE)
    {
      if (trampoline_allocate_page (page + PAGE_SIZE) == (void *) -1)
        return -1;

      trampoline_page = xrealloc (trampoline_page, ++trampoline_page_count * sizeof (void *));
      trampoline_page[i + 1] = page + PAGE_SIZE;
    }
  }
  
  __x86_setup_trampoline (from, to);
  
  return 0;
}

struct snippet_call_info *
snippet_call_info_new (int type)
{
  struct snippet_call_info *new;
  
  new = xmalloc (sizeof (struct snippet_call_info));
  
  memset (new, 0, sizeof (struct snippet_call_info));
  
  new->call_type = type;
  new->arg_list = NULL;
  new->arg_count = 0;
  
  return new;
}

void
snippet_set_address (struct snippet_call_info *info, void *addr, size_t len)
{
  info->snippet = addr;
  info->len = len;
}

void
snippet_append_argument (struct snippet_call_info *info, void *dword)
{
  info->arg_list = xrealloc (info->arg_list, (info->arg_count + 1) * sizeof (void *));
  info->arg_list[info->arg_count++] = dword;
}

void
__snippet_x86_set_reg (struct snippet_call_info *info, int reg, reg_t data)
{
  info->context.registers[reg] = data;
}

int
snippet_setup_stack (struct snippet_call_info *info, int size, int prot)
{
  void *addr;
  
  if ((addr = mmap (NULL, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0)) == (void *) -1)
  {
    error ("couldn't allocate stack: %s\n", strerror (errno));
    return -1;
  }
  
  info->context.stack_top  = addr;
  info->context.stack_size = size;
  info->context.stack_prot = prot;
  
  return 0;
}

void
__snippet_x86_enter (struct snippet_call_info *info)
{
  void *esp;
  static struct snippet_call_info *save;
  static void *snippet_addr;
  static int arg_count;
  static int saved_esp;
  char *regs[] = {"%edi", "%esi", "%ebp", "%esp", "%ebx", "%edx", "%ecx", "%eax"};
  int i;
  
  
  /* We have to make room in our stack to hold information about registers,
     arguments and saved %esp (the %esp in this function) */
     
  esp = info->context.stack_top + info->context.stack_size 
        - sizeof (info->context.registers)
        - sizeof (void *) * info->arg_count;
        
  memcpy (esp, info->context.registers, sizeof (info->context.registers));
  memcpy (esp + sizeof (info->context.registers), info->arg_list, sizeof (void *) * info->arg_count);
  
  save = info;
  snippet_addr = save->snippet;
  arg_count = sizeof (void *) * save->arg_count;
  /* CALL_TYPE_PASCAL? We must alter info->context.registers in order to
     perform a call of this type */
     
  if (mark_output)
    mark ();
    
  asm volatile ("pusha");
  asm volatile ("movl %%esp, %0" : "=g" (saved_esp));
  asm volatile ("movl %0, %%esp" :: "g" (esp));
  asm volatile ("popa" ::: "eax", "ebx", "ecx", "edx", "esi", "edi");
  asm volatile ("pushl $ret_point");
  asm volatile ("pushl %0" :: "m" (snippet_addr));
  asm volatile ("cmp $0, %0" :: "m" (do_trap));
  asm volatile ("jz 1f");
  asm volatile ("int $3");
  asm volatile ("1:");
  asm volatile ("ret"); /* I call this retrocalling */
  asm volatile ("ret_point:");
  asm volatile ("pusha");
  asm volatile ("addl $32, %esp");
  /* Adjust stack pointer */
  asm volatile ("addl %0, %%esp" :: "g" (arg_count));
  asm volatile ("movl %0,%%esp" :: "g" (saved_esp));
  asm volatile ("popa" ::: "eax", "ebx", "ecx", "edx", "esi", "edi");
  
  if (mark_output)
    mark ();
    
  memcpy (info->context.registers, esp, sizeof (info->context.registers));
  
  if (print_regdump)
  {
    fprintf (stderr, "regdump:\n");
    
    for (i = 7; i >= 4; i--)
      fprintf (stderr, "  %s = 0x%08x", regs[i], info->context.registers[i]);
      
    puts ("");
    
    for (i = 3; i >= 0; i--)
      fprintf (stderr, "  %s = 0x%08x", regs[i], info->context.registers[i]);
    
    puts ("");
  }
  
  info->retval = info->context.registers[X86_REG_EAX];
}

             
void
generic_sigaction (int sig, siginfo_t *info, void *unused)
{
  int addr;
  asm volatile ("movl 4(%%ebp), %%eax" : "=a" (addr));
  
  sig = (int) unused; /* shut up gcc */
  
  siginfo = *info;
  siglongjmp (env, addr);
}

void
handle_all (void)
{
  int i;  
  struct sigaction action;
  stack_t ss;

  ss.ss_sp = sighandler_stack_top;
  ss.ss_size = SIGHANDLER_STACK_SIZE; 
  ss.ss_flags = SS_ONSTACK; 
  
  if (sigaltstack (&ss, NULL) == -1) 
  {
    error ("can't setup a safe stack for signal handling\n");
    exit (1);
  }
  
  action.sa_sigaction = generic_sigaction;
  action.sa_flags = SA_ONESHOT | SA_SIGINFO | SA_ONSTACK;
  
  for (i = 0; i < (int) sizeof (failure_sigs) / (int) sizeof (int); i++)
    sigaction (failure_sigs[i], &action, NULL);
}

void
restore_all (void)
{
  int i;
  struct sigaction action;
  
  action.sa_handler = SIG_DFL;
  action.sa_flags = 0;
  
  for (i = 0; i < (int) sizeof (failure_sigs) / (int) sizeof (int); i++)
    sigaction (failure_sigs[i], &action, NULL);
}


void
snippet_enter (struct snippet_call_info *info)
{
  int n;
  
  handle_all ();
    
  debug ("executing snippet at %p (stack: %p-%p)\n",
    info->snippet,
    info->context.stack_top,
    info->context.stack_top + info->context.stack_size - 1);
    
  if ((n = sigsetjmp (env, 1)) == 0)
  {
    __snippet_x86_enter (info);
    siglongjmp (env, 1);
  }
  else if (n == 1)
  {
    if (print_retval)
      notice ("everything ok, snippet returned %d (0x%08x, %uu)\n", 
       info->retval, info->retval, info->retval);
  }
  else
  {
    if (mark_output)
      mark ();
    
    warning ("snippet received signal %d (%s) at 0x%x\n",
      siginfo.si_signo, strsignal (siginfo.si_signo), n);
      
    if (print_siginfo)
    {
      fprintf (stderr, "\nsiginfo at the time of failure:\n");
#define STRINGIFY(token) #token

#define DEBUG_FIELD(field, fmt, type)                                 \
    fprintf (stderr, "  ." STRINGIFY (field) " = " fmt "\n", (type) (siginfo.field))
      
      DEBUG_FIELD (si_signo, "%d,", int);
      DEBUG_FIELD (si_errno, "%d,", int);
      DEBUG_FIELD (si_code, "%d,", int);
      DEBUG_FIELD (si_pid, "%d,", int);
      DEBUG_FIELD (si_uid, "%d,", int);
      DEBUG_FIELD (si_status, "%d,", int);
      DEBUG_FIELD (si_utime, "%d,", int);
      DEBUG_FIELD (si_stime, "%d,", int);
      DEBUG_FIELD (si_int, "%d,", int);
      DEBUG_FIELD (si_ptr, "%p,", void *);
      DEBUG_FIELD (si_addr, "%p,", void *);
      DEBUG_FIELD (si_band, "%d,", int);
      DEBUG_FIELD (si_fd, "%d", int);
      
#undef DEBUG_FIELD
#undef STRINGIFY
     } 
  }
  
  restore_all ();
}

void
help (const char *argv0)
{
  fprintf (stderr, "Usage:\n");
  fprintf (stderr, "  %s [OPTIONS] <snippet> [type1:arg1 [type2:arg2 [...]]]\n",
   argv0);
  fprintf (stderr, "\n");
  fprintf (stderr, "%s runs code snippets (probably functions) extracted \n",
    argv0);
  fprintf (stderr, "from executable files, no matter their format or operating system. \n");
  fprintf (stderr, "\n");
  fprintf (stderr, "OPTIONS\n");
  fprintf (stderr, "\n");
  fprintf (stderr, "  -b, --base <addr>        specifies the base address where the\n"
                   "                           snippet should be placed.\n");
  fprintf (stderr, "  -f, --bind-function <library>:<symbol>:<address>\n");
  fprintf (stderr, "                           creates a binding to the external\n");
  fprintf (stderr, "                           function specified by <symbol> inside\n");
  fprintf (stderr, "                           <library> at <address>\n");
  fprintf (stderr, "  -e, --show-result        displays the return value of the snippet\n");
  fprintf (stderr, "  -r. --show-registers     displays the state of the registers when\n");
  fprintf (stderr, "                           the snippet exits normally\n");
  fprintf (stderr, "  -m. --show-mark          displays a horizontal line before and \n");
  fprintf (stderr, "                           after the execution.\n");
  
  fprintf (stderr, "  -s, --show-siginfo       when the snippet fails and receives a\n");
  fprintf (stderr, "                           signal, displays a dump of the siginfo\n");
  fprintf (stderr, "                           structure.\n");
  fprintf (stderr, "  -T, --debug              raises SIGTRAP the moment before jumping\n");
  fprintf (stderr, "                           to the snippet code\n");
  fprintf (stderr, "  -v, --verbose            enable some debug messages\n");
  fprintf (stderr, "  -h, --help               this help\n");
  fprintf (stderr, "  \n");
  
  fprintf (stderr, "Snippet argument syntax:\n");
  fprintf (stderr, "The snippet can be executed with arguments passed on the stack\n");
  fprintf (stderr, "like a standard C function in a few formats. Arguments must\n");
  fprintf (stderr, "have the following syntax:\n\n");
  fprintf (stderr, "  type:value\n\n");
  fprintf (stderr, "The format of `value' depends of the type of the argument we're\n");
  fprintf (stderr, "passing to the snippet, and can be one of the following:\n\n");
  fprintf (stderr, "  s, str:                  Passes a pointer to a string to the\n");
  fprintf (stderr, "                           snippet. Value can be any string\n");
  fprintf (stderr, "                           literal.\n");
  fprintf (stderr, "  i, int:                  Passes a signed 32-bit integer. Value\n");
  fprintf (stderr, "                           must be a decimal, octal or hexadecimal\n");
  fprintf (stderr, "                           number in C format. Hexadecimal values\n\n");
  fprintf (stderr, "                           beyond 0x7fffffff will be mangled, being.\n\n");
  fprintf (stderr, "                           converted to 0x7fffffff.\n\n");
  
  fprintf (stderr, "  u, uint:                 Passes an unsigned 32-bit decimal\n");
  fprintf (stderr, "  x, hex:                  Passes an unsigned 32-bit hexadecimal,\n");
  fprintf (stderr, "                           lower or upper case, starting with `0x'\n");
  
 
  fprintf (stderr, "(c) 2011 BatchDrake <BatchDrake(at)gmail(dot)com>\n");
  fprintf (stderr, "(c) 2011 Painsec <http://www.painsec.com>\n");
  fprintf (stderr, "\n");
  fprintf (stderr, "Copyrighted but free, under the terms of GPL3 license\n");
}

int
load_snippet (const char *path, void *addr, void **place)
{
  int fd;
  int flags;
  off_t offset;
  int len;
  
  if ((fd = open (path, O_RDONLY)) == -1)
    return -1;
    
  len = lseek (fd, 0, SEEK_END);
  lseek (fd, 0, SEEK_SET);
  
  flags = (addr != NULL) * MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
  
  offset = (off_t) ((busword_t) addr & PAGE_OFFSET_MASK);
  addr = (void *) ((busword_t) addr & ~(busword_t) PAGE_OFFSET_MASK);
  
  if ((addr = mmap (addr, len + offset + MMAP_EXTRA_BYTES, PROT_EXEC | PROT_READ | PROT_WRITE, flags, 0, 0)) == (void *) -1)
  {
    error ("mmap filed: %s\n", strerror (errno));
    close (fd);
    return -1;
  }

  if (read (fd, addr + offset, len) < len)
  {
    error ("short read: %s\n", strerror (errno));
    munmap (addr, len + offset);
    close (fd);
    
    return -1;
  }
  
  close (fd);
  
  memset (addr, NOP_BYTE, offset);
  *place = addr + offset;
  
  return len;
}

void *
lib_open (const char *path)
{
  void *handle;
  int i;
  struct lib_info *new;
  
  for (i = 0; i < libs_count; i++)
    if (strcmp (libs_list[i]->name, path) == 0)
      return libs_list[i]->handle;
      
  if ((handle = dlopen (path, RTLD_LAZY)) == NULL)
    return NULL;
  
  new = xmalloc (sizeof (struct lib_info));
  
  new->name = xstrdup (path);
  new->handle = handle;
  
  PTR_LIST_APPEND (libs, new);
  
  return handle;
}


void
queue_trampoline (void *from, void *to)
{
  struct trampoline *tramp;
  
  tramp = xmalloc (sizeof (struct trampoline));
  
  tramp->from = from;
  tramp->to = to;
  
  PTR_LIST_APPEND (trampolines, tramp);
}

void
setup_trampolines (void)
{
  int i;
  
  for (i = 0; i < trampolines_count; i++)
    if (trampoline_register (trampolines_list[i]->from, trampolines_list[i]->to)  == -1)
    {
      error ("trampoline allocation failed for binding %p to %p\n", 
        trampolines_list[i]->from, trampolines_list[i]->to);
      exit (1);
    }
}

int
main (int argc, char **argv)
{
  int len;
  int i;
  int n;
  char *type, *value;
  int index;
  
  char *name, *lib, *where;
  void *addr;
  void *handle;
  char c;
  int params = 0;
  
  static struct option long_options[] = 
  {
    {"bind-function", 1, 0, 'f'},
    {"base", 1, 0, 'b'},
    {"show-siginfo", 0, 0, 's'},
    {"verbose", 0, 0, 'v'},
    {"debug", 0, 0, 'T'},
    {"show-result", 0, 0, 'e'},
    {"show-registers", 0, 0, 'r'},
    {"show-mark", 0, 0, 'm'},
    
    {"help", 1, 0, 'h'},
    
    {0, 0, 0, 0}
  };
               
  base = NULL;
  
  struct snippet_call_info *info;
 
  while ((c = getopt_long (argc, argv, "b:f:srvemTh", long_options, &index)) != -1)
    switch (c)
    {
      case 'b':
        if (!sscanf (optarg, "%i", (int *) &base))
        {
          fprintf (stderr, "%s: wrong base address\n", argv[0]);
          exit (1);
        }
        
        break;
      
      case 'm':
        mark_output++;
        break;
        
      case 'T':
        do_trap++;
        break;
        
      case 's':
        print_siginfo++;
        break;
        
      case 'r':
        print_regdump++;
        break;
        
      case 'e':
        print_retval++;
        break;
      
      case 'v':
        verbose++;
        break;
        
      /* Calling convention missing */
      case 'f':
        name = xmalloc (strlen (optarg));
        lib = xmalloc (strlen (optarg));
        
        if (sscanf (optarg, "%[^:]:%[^:]:%i", lib, name, (int *) &where) != 3)
        {
          fprintf (stderr, "%s: wrong function binding syntax\n", argv[0]);
          exit (1);
        }
        
        if ((handle = lib_open (lib)) == NULL)
        {
          fprintf (stderr, "%s: couldn't open %s: %s\n", argv[0], lib, dlerror ());
          exit (1);
        }
        
        /* No NULL symbols accepted, period. */
        if ((addr = dlsym (handle, name)) == NULL)
        {
          fprintf (stderr, "%s: symbol `%s' either NULL or not found\n", argv[0], name);
          exit (1);
        }
        
        queue_trampoline (where, addr);
        
        free (name);
        free (lib);
        
        break;
      
      
      case 'h':
        help (argv[0]);
        return 0;

        
      case '?':
        if (isprint (c))
        {
          help (argv[0]);
          exit (1);
        }
    }
    
  
  for (i = optind; i < argc; i++)
  {
    if (!params++)
    {
      if ((len = load_snippet (argv[i], base, &base)) == -1)
      {
        fprintf (stderr, "%s: %s: couldn't load snippet: %s\n",
          argv[0], argv[i], strerror (errno));
          
        exit (1);
      }
      
      info = snippet_call_info_new (CALL_TYPE_STDCALL);
    }
    else
    {
      type = xmalloc (strlen (argv[i]));
      value = xmalloc (strlen (argv[i]));
      
      if (sscanf (argv[i], "%[^:]:%[^:]", type, value) != 2)
      {
        fprintf (stderr, "%s: invalid argument description\n", argv[0]);
        exit (1);
      }
      
      if (strcmp (type, "s") == 0 || strcmp (type, "str") == 0)
        snippet_append_argument (info, xstrdup (value));
      else if (strcmp (type, "i") == 0 || strcmp (type, "int") == 0)
      {
        if (!sscanf (value, "%i", &n))
        {
          fprintf (stderr, "%s: invalid integer value \"%s\"\n", argv[0], value);
          exit (1);
        }
        snippet_append_argument (info, (void *) n);
      }
      else if (strcmp (type, "u") == 0 || strcmp (type, "uint") == 0)
      {
        if (!sscanf (value, "%u", &n))
        {
          fprintf (stderr, "%s: invalid integer value \"%s\"\n", argv[0], value);
          exit (1);
        }
        snippet_append_argument (info, (void *) n);
      }
      else if (strcmp (type, "x") == 0 || strcmp (type, "hex") == 0)
      {
        if (!sscanf (value, "0x%x", &n))
        {
          fprintf (stderr, "%s: invalid integer value \"%s\"\n", argv[0], value);
          exit (1);
        }
        snippet_append_argument (info, (void *) n);
      }
      else
      {
        fprintf (stderr, "%s: invalid argument type `%s' '\n", argv[0], type);
        exit (1);
      }
      
      free (type);
      free (value);
    }
  }
  
  if (params == 0)
  {
    fprintf (stderr, "%s: no input file given\n", argv[0]);
    help (argv[0]);
    exit (1);
  }

  sighandler_stack_top = xmalloc (SIGHANDLER_STACK_SIZE);
  
  debug ("alternative stack was allocated: 0x%08x\n", (unsigned int) sighandler_stack_top);
  snippet_set_address (info, base, len);
  snippet_setup_stack (info, DEFAULT_STACK_SIZE, PROT_READ | PROT_WRITE);
  setup_trampolines ();
  snippet_enter (info);
  
  return 0;  
}

