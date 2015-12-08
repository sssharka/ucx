/*
 * * Copyright (C) International Business Machines Corp. 2001-2015.  ALL RIGHTS RESERVED.
 * * See file LICENSE for terms.
 * */

#ifndef  __COMMON_IBV_MEMORY_SYSCALL_HOOK_H__
#define  __COMMON_IBV_MEMORY_SYSCALL_HOOK_H__

#include <assert.h>
#include <dlfcn.h>
#include <malloc.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <vector>

#if defined(__PPC64__)
#include <arch/ppc64/BuildInstructions.h>
#endif

#undef TRACE_ERR
#define TRACE_ERR(x) //fprintf x

//////////////////////////////////////////////////////////////////
///  The glib sys call hook to enable intercepting select 
///  glibc system functions. Typically used for memory monitoring and
///  invalidating memory region caches. This code is based on a
///  similar memory system hook in the LAPI messaging libraries
//////////////////////////////////////////////////////////////////

namespace PAMI
{
  //Glibc Memory Syscall hook for invalidating the memregion cache
  class MemSyscallIntercept {
  protected:
    static const size_t MAX_PATCH_LEN = 32;    

    class PatchState {
    protected:
      size_t    _addr;                     //Address of hook
      size_t    _length;                   //patch length
      char      _patchELF [MAX_PATCH_LEN]; //ELF state of the patched binary
      char      _baseELF  [MAX_PATCH_LEN]; //ELF state of the original binary

      static int buildPPCELF(size_t addr, unsigned int reg, size_t value)
      {
#if defined(__PPC64__)
        *(unsigned int *) (addr + 0) = PPC64::addis ( reg, 0,   (value >> 48));
        *(unsigned int *) (addr + 4) = PPC64::ori   ( reg, reg, (value >> 32));
        *(unsigned int *) (addr + 8) = PPC64::rldicr( reg, reg, 32, 31);
        *(unsigned int *) (addr +12) = PPC64::oris  ( reg, reg, (value >> 16));
        *(unsigned int *) (addr +16) = PPC64::ori   ( reg, reg, (value >>  0));
#endif
        return 20;
      }
      // modify protection of memory range
      void modifyMemoryProtection(int prot) {
	long    page_size = sysconf(_SC_PAGE_SIZE);
	size_t  page_addr = (_addr & ~(page_size-1));
	if (mprotect((void *)page_addr, page_size, prot))
	  perror("MemHook: mprotect failed");
      }      

      //Save the system original state and build a patch that points
      //to the hook address
      void saveSystemState (const char *func_name, size_t hook_addr) {
	// get system function address
	size_t sys_addr = (size_t)dlsym(RTLD_NEXT, func_name);
	if(sys_addr == 0) sys_addr = (size_t)dlsym(RTLD_DEFAULT, func_name);
#if defined(__PPC64__) 
#if _CALL_ELF != 2
#error "does not work"
	// ppc64 uses indirect function pointers
	if (sys_addr)
	  sys_addr  = *(size_t *)sys_addr;
	if (hook_addr)
	  hook_addr = *(size_t *)hook_addr;
#else 
	sys_addr  += 8;
	hook_addr += 8;
#endif //endif _CALL_ELF != 2
#endif //endif (__PPC64__)

	_addr = sys_addr;

	// generate patch code and save it
#if defined(__x86_64__)
	// movabs hook_addr,%r11
	// jmpq   *%r11
	*(unsigned short *) (_patchELF + 0) = 0xbb49;
	*(unsigned long  *) (_patchELF + 2) = hook_addr;
	*(unsigned char  *) (_patchELF +10) = 0x41;
	*(unsigned char  *) (_patchELF +11) = 0xff;
	*(unsigned char  *) (_patchELF +12) = 0xe3;
	_length = 13;
#elif defined(__PPC64__)
	// r11 is a volatile register according to PowerPC EABI
	const unsigned int gr = 11;
	int offset = buildPPCELF((size_t)_patchELF, gr, hook_addr);
	// 9 = CTR
	*(unsigned int *)(_patchELF+offset+0) = PPC64::mtspr(9, gr);   
	// 20 = always
	*(unsigned int *)(_patchELF+offset+4) = PPC64::bcctr(20, 0, 0);
	_length = offset + 8;
#else
#error "Unknown Unsupported Architecture"
#endif	
	// save the original code
	assert(_length <= MAX_PATCH_LEN);
	memcpy(_baseELF, (void *)_addr, _length);
      }
      
    public:            
      //The hook address here must ignore the preamble
      void saveHookState (size_t hook_addr) {
	//On all architectures except PPC64
	_addr   = 0;
	_length = 0;
#if defined(__PPC64__)
	// generate code to restore TOC
	register unsigned long toc asm("r2");
	_addr   = hook_addr;
	_length = buildPPCELF((size_t)_patchELF, 2, toc);	
	// save the original code
	assert(_length <= MAX_PATCH_LEN);
	memcpy(_baseELF, (void *)_addr, _length);
#endif	
      }

      PatchState () : _addr(0), _length(0) { /* default constructor */ }

      PatchState (const char *sys_name, size_t hook_addr) {
	saveSystemState (sys_name, hook_addr);
      }
      
      void activate () {
	TRACE_ERR((stderr, "PatchState::activate\n"));
	if (_length == 0) return;
	modifyMemoryProtection(PROT_EXEC|PROT_READ|PROT_WRITE);
	memcpy((void *)_addr, _patchELF, _length);
	modifyMemoryProtection(PROT_EXEC|PROT_READ);
	TRACE_ERR((stderr, "PatchState::activate done\n"));
      }
      
      void revert() {
	if (_length == 0) return;
	modifyMemoryProtection(PROT_EXEC|PROT_READ|PROT_WRITE);
	memcpy((void *)_addr, _baseELF, _length);
	modifyMemoryProtection(PROT_EXEC|PROT_READ);
      }
    };  //-- PatchState
    
    //A pair of patches for the system TOC and hook TOC
    class SysIntercept {
    public:
      SysIntercept(const char *sys_func, size_t hook_addr) :
	_sys  (sys_func, hook_addr),  //saveSystemState constructor
	_hook () //default constructor
      {	
#if defined(__PPC64__) 
#if _CALL_ELF != 2
#error "does not work"
	//find hook address without preamble
	// ppc64 uses indirect function pointers
	if (hook_addr)
	  hook_addr = *(size_t *)hook_addr;
#endif	
	// locate reserved code space in hook function
	unsigned int *nop_addr = (unsigned int *)hook_addr;
	const unsigned int nop = 0x60000000;
	for (; ; nop_addr++)
	  if (nop_addr[0] == nop && nop_addr[1] == nop && nop_addr[2] == nop
	      && nop_addr[3] == nop && nop_addr[4] == nop)
            break;
	_hook.saveHookState ((size_t) nop_addr);
#endif
      }
      
      void activate() {
	_sys.activate();
	_hook.activate();
      }
      void revert() {
	_sys.revert();
	_hook.revert();
      }
      
    protected:
      PatchState     _sys;    //Save the system state
      PatchState     _hook;   //Save the state of the hook (for PPC only)
    };
    
    static SysIntercept  interceptions[]; 
    static size_t n_intercept;     

    // replacements for system functions
    static int   Unmap(void *start, size_t length);
    static void *Remap(void *old_address, size_t old_size , size_t new_size, int flags);
    static int   Brk(void* addr);

    void init () {
      TRACE_ERR((stderr, "MemSyscallIntercept::init\n"));
      for (size_t i = 0; i < n_intercept; ++i)
	interceptions[i].activate();
      //LAPI manipulated malloc via mallopt. that can be added here!
      TRACE_ERR((stderr, "MemSyscallIntercept::init done\n"));
    }

  public:
    enum Event_t { EVENT_none, EVENT_munmap, EVENT_mremap, EVENT_brk };
    typedef void   (*EventFunction_t) ( Event_t      eventid,
					void       * clientdata,
					void       * address,
					size_t       length );   
    //Event pair definition
    typedef std::pair<EventFunction_t, void *> EventPair_t;

    MemSyscallIntercept () { /*constructor*/ }

    void registerEventFunction (EventFunction_t  fn, void *cd) {
      TRACE_ERR((stderr, "MemSyscallIntercept::registerEventFunction\n"));
      if (_eventVec.size() == 0) init();      
      std::pair<EventFunction_t, void *> mypair(fn, cd);
      _eventVec.push_back(mypair);
    }

    void unRegisterEventFunction (EventFunction_t fn) {
      std::vector<EventPair_t>::iterator it;
      for (it = _eventVec.begin(); it < _eventVec.end(); ++it)
	if (it->first == fn) {
	  _eventVec.erase(it);
	  break;
	}
      if (_eventVec.size() == 0)
	//we unregistered all callbacks, so deactivate patches
	for (size_t i = 0; i < n_intercept; ++i)
	  interceptions[i].revert();      
    }

    void callEventFn (Event_t event, void *start, size_t size) {
      std::vector<EventPair_t>::iterator it;
      for(it = _eventVec.begin(); it < _eventVec.end(); ++it) 
	(*it->first) (event, it->second, start, size);
    }
   
  protected:
    std::vector<EventPair_t>       _eventVec;
  }; //MemSyscallIntercept
};  //PAMI

#if defined(__PPC64__)
// special processing for ppc64 to save and restore TOC (r2)
// Reference: "64-bit PowerPC ELF Application Binary Interface Supplement 1.9"
#define MEMHOOK_PROLOGUE \
    unsigned long toc_save; \
    asm volatile ("std 2, %0" : "=m" (toc_save)); \
    asm volatile ("nop; nop; nop; nop; nop")

#define MEMHOOK_EPILOGUE			\
  asm volatile ("ld  2, %0" : : "m" (toc_save));	\
  return result
#else // !__PPC64__
#define MEMHOOK_PROLOGUE
#define MEMHOOK_EPILOGUE      return result
#endif

extern PAMI::MemSyscallIntercept &mintercept;

// hook function matching system munmap function
inline int PAMI::MemSyscallIntercept::Unmap(void *start, size_t length)
{
  MEMHOOK_PROLOGUE;
  TRACE_ERR((stderr, "MemSyscallIntercept::Unmap\n"));
  mintercept.callEventFn(EVENT_munmap, start, length);
  int result = syscall(SYS_munmap, start, length);	  
  MEMHOOK_EPILOGUE;
}

// hook function matching system mremap function
inline void *PAMI::MemSyscallIntercept::Remap(void *old_address, size_t old_size , size_t new_size, int flags) {
  MEMHOOK_PROLOGUE;
  TRACE_ERR((stderr, "MemSyscallIntercept::Remap\n"));
  mintercept.callEventFn(EVENT_mremap, old_address, old_size);
  void *result = (void *)syscall(SYS_mremap, old_address, old_size, new_size, flags);
  MEMHOOK_EPILOGUE;
}

extern "C" void* __curbrk; //in glibc malloc implementation
// hook function matching system brk function
inline int PAMI::MemSyscallIntercept::Brk(void *addr) {
    MEMHOOK_PROLOGUE;
    TRACE_ERR((stderr, "MemSyscallIntercept::Brk\n"));
    int result;
    void* old_addr = __curbrk;
    void* new_addr;
    new_addr = __curbrk = (void *) syscall(SYS_brk, addr);
    if (new_addr < addr) {
      errno = ENOMEM;
      result = -1;
    } else {
      /* data segment is truncated */
      if (new_addr < old_addr) {
	size_t len = (size_t)old_addr - (size_t)new_addr + 1;
	assert(addr == new_addr);
	mintercept.callEventFn(EVENT_brk, addr, len);
      }
      result = 0;
    }
    MEMHOOK_EPILOGUE;
}

#endif
