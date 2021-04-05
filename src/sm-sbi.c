//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "sm-sbi.h"
#include "pmp.h"
#include "enclave.h"
#include "page.h"
#include "cpu.h"
#include "platform-hook.h"
#include "plugins/plugins.h"
#include <sbi/riscv_asm.h>
#include <sbi/sbi_console.h>

unsigned long sbi_sm_create_enclave(unsigned long* eid, uintptr_t create_args)
{
  struct keystone_sbi_create create_args_local;
  unsigned long ret;

  ret = copy_enclave_create_args(create_args, &create_args_local);

  if (ret)
    return ret;

  ret = create_enclave(eid, create_args_local);
  return ret;
}

unsigned long sbi_sm_destroy_enclave(unsigned long eid)
{
  unsigned long ret;
  ret = destroy_enclave((unsigned int)eid);
  return ret;
}

unsigned long sbi_sm_run_enclave(struct sbi_trap_regs *regs, unsigned long eid)
{
  /* update policy counter by reading from CSR mcycle/minstret */
  // enclave_policies[eid].instr_count = (uint64_t)csr_read(minstret);
  // enclave_policies[eid].cycle_count = (uint64_t)csr_read(mcycle);

  regs->a0 = run_enclave(regs, (unsigned int) eid);
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_resume_enclave(struct sbi_trap_regs *regs, unsigned long eid)
{
  /* update policy counter by reading from CSR mcycle/minstret */
  // enclave_policies[eid].instr_count = (uint64_t)csr_read(minstret);
  // enclave_policies[eid].cycle_count = (uint64_t)csr_read(mcycle);

  unsigned long ret;
  ret = resume_enclave(regs, (unsigned int) eid);
  if (!regs->zero)
    regs->a0 = ret;
  regs->mepc += 4;

  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_exit_enclave(struct sbi_trap_regs *regs, unsigned long retval)
{
    /* calculate policy counter */
  int eid = cpu_get_enclave_id();
  //enclave_policies[eid].instr_run_tot = enclave_policies[eid].instr_run_tot + ((uint64_t)csr_read(minstret) - enclave_policies[eid].instr_count);
  //enclave_policies[eid].cycles_run_tot = enclave_policies[eid].cycles_run_tot + ((uint64_t)csr_read(mcycle) - enclave_policies[eid].cycle_count);
  //sbi_printf("EID: %5x, %10s %10lu, %10s %10lu\n", eid, "instr_run_total:", enclave_policies[eid].instr_run_tot, "cycles_run_total:", enclave_policies[eid].cycles_run_tot);

  regs->a0 = exit_enclave(regs, eid);
  regs->a1 = retval;
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_stop_enclave(struct sbi_trap_regs *regs, unsigned long request)
{
  /* calculate policy counter */
  int eid = cpu_get_enclave_id();
  //enclave_policies[eid].instr_run_tot = enclave_policies[eid].instr_run_tot + ((uint64_t)csr_read(minstret) - enclave_policies[eid].instr_count);
  //enclave_policies[eid].cycles_run_tot = enclave_policies[eid].cycles_run_tot + ((uint64_t)csr_read(mcycle) - enclave_policies[eid].cycle_count);
  //sbi_printf("EID: %5d, %10s %10lu, %10s %10lu\n", eid, "instr_run_total:", enclave_policies[eid].instr_run_tot, "cycles_run_total:", enclave_policies[eid].cycles_run_tot);

  regs->a0 = stop_enclave(regs, request, eid);
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size)
{
  unsigned long ret;
  ret = attest_enclave(report, data, size, cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                       size_t key_ident_size)
{
  unsigned long ret;
  ret = get_sealing_key(sealing_key, key_ident, key_ident_size,
                         cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_random()
{
  return (unsigned long) platform_random();
}

unsigned long sbi_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id, uintptr_t arg0, uintptr_t arg1)
{
  unsigned long ret;
  ret = call_plugin(cpu_get_enclave_id(), plugin_id, call_id, arg0, arg1);
  return ret;
}
