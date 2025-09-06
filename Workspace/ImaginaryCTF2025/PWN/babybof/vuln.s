
vuln:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	48 83 ec 08          	sub    $0x8,%rsp
  401008:	48 8b 05 d1 2f 00 00 	mov    0x2fd1(%rip),%rax        # 403fe0 <__gmon_start__@Base>
  40100f:	48 85 c0             	test   %rax,%rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   *%rax
  401016:	48 83 c4 08          	add    $0x8,%rsp
  40101a:	c3                   	ret

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 ca 2f 00 00    	push   0x2fca(%rip)        # 403ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	ff 25 cc 2f 00 00    	jmp    *0x2fcc(%rip)        # 403ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102c:	0f 1f 40 00          	nopl   0x0(%rax)
  401030:	f3 0f 1e fa          	endbr64
  401034:	68 00 00 00 00       	push   $0x0
  401039:	e9 e2 ff ff ff       	jmp    401020 <_init+0x20>
  40103e:	66 90                	xchg   %ax,%ax
  401040:	f3 0f 1e fa          	endbr64
  401044:	68 01 00 00 00       	push   $0x1
  401049:	e9 d2 ff ff ff       	jmp    401020 <_init+0x20>
  40104e:	66 90                	xchg   %ax,%ax
  401050:	f3 0f 1e fa          	endbr64
  401054:	68 02 00 00 00       	push   $0x2
  401059:	e9 c2 ff ff ff       	jmp    401020 <_init+0x20>
  40105e:	66 90                	xchg   %ax,%ax
  401060:	f3 0f 1e fa          	endbr64
  401064:	68 03 00 00 00       	push   $0x3
  401069:	e9 b2 ff ff ff       	jmp    401020 <_init+0x20>
  40106e:	66 90                	xchg   %ax,%ax
  401070:	f3 0f 1e fa          	endbr64
  401074:	68 04 00 00 00       	push   $0x4
  401079:	e9 a2 ff ff ff       	jmp    401020 <_init+0x20>
  40107e:	66 90                	xchg   %ax,%ax

Disassembly of section .plt.sec:

0000000000401080 <puts@plt>:
  401080:	f3 0f 1e fa          	endbr64
  401084:	ff 25 76 2f 00 00    	jmp    *0x2f76(%rip)        # 404000 <puts@GLIBC_2.2.5>
  40108a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000401090 <__stack_chk_fail@plt>:
  401090:	f3 0f 1e fa          	endbr64
  401094:	ff 25 6e 2f 00 00    	jmp    *0x2f6e(%rip)        # 404008 <__stack_chk_fail@GLIBC_2.4>
  40109a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000004010a0 <setbuf@plt>:
  4010a0:	f3 0f 1e fa          	endbr64
  4010a4:	ff 25 66 2f 00 00    	jmp    *0x2f66(%rip)        # 404010 <setbuf@GLIBC_2.2.5>
  4010aa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000004010b0 <printf@plt>:
  4010b0:	f3 0f 1e fa          	endbr64
  4010b4:	ff 25 5e 2f 00 00    	jmp    *0x2f5e(%rip)        # 404018 <printf@GLIBC_2.2.5>
  4010ba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000004010c0 <gets@plt>:
  4010c0:	f3 0f 1e fa          	endbr64
  4010c4:	ff 25 56 2f 00 00    	jmp    *0x2f56(%rip)        # 404020 <gets@GLIBC_2.2.5>
  4010ca:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

Disassembly of section .text:

00000000004010d0 <_start>:
  4010d0:	f3 0f 1e fa          	endbr64
  4010d4:	31 ed                	xor    %ebp,%ebp
  4010d6:	49 89 d1             	mov    %rdx,%r9
  4010d9:	5e                   	pop    %rsi
  4010da:	48 89 e2             	mov    %rsp,%rdx
  4010dd:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  4010e1:	50                   	push   %rax
  4010e2:	54                   	push   %rsp
  4010e3:	45 31 c0             	xor    %r8d,%r8d
  4010e6:	31 c9                	xor    %ecx,%ecx
  4010e8:	48 c7 c7 bf 11 40 00 	mov    $0x4011bf,%rdi
  4010ef:	ff 15 db 2e 00 00    	call   *0x2edb(%rip)        # 403fd0 <__libc_start_main@GLIBC_2.34>
  4010f5:	f4                   	hlt
  4010f6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  4010fd:	00 00 00 

0000000000401100 <_dl_relocate_static_pie>:
  401100:	f3 0f 1e fa          	endbr64
  401104:	c3                   	ret
  401105:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  40110c:	00 00 00 
  40110f:	90                   	nop

0000000000401110 <deregister_tm_clones>:
  401110:	b8 40 40 40 00       	mov    $0x404040,%eax
  401115:	48 3d 40 40 40 00    	cmp    $0x404040,%rax
  40111b:	74 13                	je     401130 <deregister_tm_clones+0x20>
  40111d:	b8 00 00 00 00       	mov    $0x0,%eax
  401122:	48 85 c0             	test   %rax,%rax
  401125:	74 09                	je     401130 <deregister_tm_clones+0x20>
  401127:	bf 40 40 40 00       	mov    $0x404040,%edi
  40112c:	ff e0                	jmp    *%rax
  40112e:	66 90                	xchg   %ax,%ax
  401130:	c3                   	ret
  401131:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  401138:	00 00 00 00 
  40113c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401140 <register_tm_clones>:
  401140:	be 40 40 40 00       	mov    $0x404040,%esi
  401145:	48 81 ee 40 40 40 00 	sub    $0x404040,%rsi
  40114c:	48 89 f0             	mov    %rsi,%rax
  40114f:	48 c1 ee 3f          	shr    $0x3f,%rsi
  401153:	48 c1 f8 03          	sar    $0x3,%rax
  401157:	48 01 c6             	add    %rax,%rsi
  40115a:	48 d1 fe             	sar    $1,%rsi
  40115d:	74 11                	je     401170 <register_tm_clones+0x30>
  40115f:	b8 00 00 00 00       	mov    $0x0,%eax
  401164:	48 85 c0             	test   %rax,%rax
  401167:	74 07                	je     401170 <register_tm_clones+0x30>
  401169:	bf 40 40 40 00       	mov    $0x404040,%edi
  40116e:	ff e0                	jmp    *%rax
  401170:	c3                   	ret
  401171:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  401178:	00 00 00 00 
  40117c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401180 <__do_global_dtors_aux>:
  401180:	f3 0f 1e fa          	endbr64
  401184:	80 3d cd 2e 00 00 00 	cmpb   $0x0,0x2ecd(%rip)        # 404058 <completed.0>
  40118b:	75 13                	jne    4011a0 <__do_global_dtors_aux+0x20>
  40118d:	55                   	push   %rbp
  40118e:	48 89 e5             	mov    %rsp,%rbp
  401191:	e8 7a ff ff ff       	call   401110 <deregister_tm_clones>
  401196:	c6 05 bb 2e 00 00 01 	movb   $0x1,0x2ebb(%rip)        # 404058 <completed.0>
  40119d:	5d                   	pop    %rbp
  40119e:	c3                   	ret
  40119f:	90                   	nop
  4011a0:	c3                   	ret
  4011a1:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  4011a8:	00 00 00 00 
  4011ac:	0f 1f 40 00          	nopl   0x0(%rax)

00000000004011b0 <frame_dummy>:
  4011b0:	f3 0f 1e fa          	endbr64
  4011b4:	eb 8a                	jmp    401140 <register_tm_clones>

00000000004011b6 <pop_rdi_ret>:
  4011b6:	f3 0f 1e fa          	endbr64
  4011ba:	5f                   	pop    %rdi
  4011bb:	c3                   	ret
  4011bc:	90                   	nop
  4011bd:	0f 0b                	ud2

00000000004011bf <main>:
  4011bf:	f3 0f 1e fa          	endbr64
  4011c3:	55                   	push   %rbp
  4011c4:	48 89 e5             	mov    %rsp,%rbp
  4011c7:	48 83 ec 40          	sub    $0x40,%rsp
  4011cb:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  4011d2:	00 00 
  4011d4:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  4011d8:	31 c0                	xor    %eax,%eax
  4011da:	48 8b 05 6f 2e 00 00 	mov    0x2e6f(%rip),%rax        # 404050 <stdin@GLIBC_2.2.5>
  4011e1:	be 00 00 00 00       	mov    $0x0,%esi
  4011e6:	48 89 c7             	mov    %rax,%rdi
  4011e9:	e8 b2 fe ff ff       	call   4010a0 <setbuf@plt>
  4011ee:	48 8b 05 4b 2e 00 00 	mov    0x2e4b(%rip),%rax        # 404040 <stdout@GLIBC_2.2.5>
  4011f5:	be 00 00 00 00       	mov    $0x0,%esi
  4011fa:	48 89 c7             	mov    %rax,%rdi
  4011fd:	e8 9e fe ff ff       	call   4010a0 <setbuf@plt>
  401202:	48 8d 05 ff 0d 00 00 	lea    0xdff(%rip),%rax        # 402008 <_IO_stdin_used+0x8>
  401209:	48 89 c7             	mov    %rax,%rdi
  40120c:	e8 6f fe ff ff       	call   401080 <puts@plt>
  401211:	48 8d 05 04 0e 00 00 	lea    0xe04(%rip),%rax        # 40201c <_IO_stdin_used+0x1c>
  401218:	48 89 c7             	mov    %rax,%rdi
  40121b:	e8 60 fe ff ff       	call   401080 <puts@plt>
  401220:	48 8b 05 b1 2d 00 00 	mov    0x2db1(%rip),%rax        # 403fd8 <system@GLIBC_2.2.5>
  401227:	48 89 c6             	mov    %rax,%rsi
  40122a:	48 8d 05 06 0e 00 00 	lea    0xe06(%rip),%rax        # 402037 <_IO_stdin_used+0x37>
  401231:	48 89 c7             	mov    %rax,%rdi
  401234:	b8 00 00 00 00       	mov    $0x0,%eax
  401239:	e8 72 fe ff ff       	call   4010b0 <printf@plt>
  40123e:	48 8d 05 75 ff ff ff 	lea    -0x8b(%rip),%rax        # 4011ba <pop_rdi_ret+0x4>
  401245:	48 89 c6             	mov    %rax,%rsi
  401248:	48 8d 05 f5 0d 00 00 	lea    0xdf5(%rip),%rax        # 402044 <_IO_stdin_used+0x44>
  40124f:	48 89 c7             	mov    %rax,%rdi
  401252:	b8 00 00 00 00       	mov    $0x0,%eax
  401257:	e8 54 fe ff ff       	call   4010b0 <printf@plt>
  40125c:	48 8d 05 58 ff ff ff 	lea    -0xa8(%rip),%rax        # 4011bb <pop_rdi_ret+0x5>
  401263:	48 89 c6             	mov    %rax,%rsi
  401266:	48 8d 05 ea 0d 00 00 	lea    0xdea(%rip),%rax        # 402057 <_IO_stdin_used+0x57>
  40126d:	48 89 c7             	mov    %rax,%rdi
  401270:	b8 00 00 00 00       	mov    $0x0,%eax
  401275:	e8 36 fe ff ff       	call   4010b0 <printf@plt>
  40127a:	48 8d 05 b7 2d 00 00 	lea    0x2db7(%rip),%rax        # 404038 <sh>
  401281:	48 89 c6             	mov    %rax,%rsi
  401284:	48 8d 05 d6 0d 00 00 	lea    0xdd6(%rip),%rax        # 402061 <_IO_stdin_used+0x61>
  40128b:	48 89 c7             	mov    %rax,%rdi
  40128e:	b8 00 00 00 00       	mov    $0x0,%eax
  401293:	e8 18 fe ff ff       	call   4010b0 <printf@plt>
  401298:	48 8d 45 c0          	lea    -0x40(%rbp),%rax
  40129c:	48 83 c0 38          	add    $0x38,%rax
  4012a0:	48 8b 00             	mov    (%rax),%rax
  4012a3:	48 89 c6             	mov    %rax,%rsi
  4012a6:	48 8d 05 c4 0d 00 00 	lea    0xdc4(%rip),%rax        # 402071 <_IO_stdin_used+0x71>
  4012ad:	48 89 c7             	mov    %rax,%rdi
  4012b0:	b8 00 00 00 00       	mov    $0x0,%eax
  4012b5:	e8 f6 fd ff ff       	call   4010b0 <printf@plt>
  4012ba:	48 8d 05 bf 0d 00 00 	lea    0xdbf(%rip),%rax        # 402080 <_IO_stdin_used+0x80>
  4012c1:	48 89 c7             	mov    %rax,%rdi
  4012c4:	b8 00 00 00 00       	mov    $0x0,%eax
  4012c9:	e8 e2 fd ff ff       	call   4010b0 <printf@plt>
  4012ce:	48 8d 45 c0          	lea    -0x40(%rbp),%rax
  4012d2:	48 89 c7             	mov    %rax,%rdi
  4012d5:	b8 00 00 00 00       	mov    $0x0,%eax
  4012da:	e8 e1 fd ff ff       	call   4010c0 <gets@plt>
  4012df:	48 8d 45 c0          	lea    -0x40(%rbp),%rax
  4012e3:	48 89 c6             	mov    %rax,%rsi
  4012e6:	48 8d 05 c9 0d 00 00 	lea    0xdc9(%rip),%rax        # 4020b6 <_IO_stdin_used+0xb6>
  4012ed:	48 89 c7             	mov    %rax,%rdi
  4012f0:	b8 00 00 00 00       	mov    $0x0,%eax
  4012f5:	e8 b6 fd ff ff       	call   4010b0 <printf@plt>
  4012fa:	48 8d 45 c0          	lea    -0x40(%rbp),%rax
  4012fe:	48 83 c0 38          	add    $0x38,%rax
  401302:	48 8b 00             	mov    (%rax),%rax
  401305:	48 89 c6             	mov    %rax,%rsi
  401308:	48 8d 05 62 0d 00 00 	lea    0xd62(%rip),%rax        # 402071 <_IO_stdin_used+0x71>
  40130f:	48 89 c7             	mov    %rax,%rdi
  401312:	b8 00 00 00 00       	mov    $0x0,%eax
  401317:	e8 94 fd ff ff       	call   4010b0 <printf@plt>
  40131c:	48 8d 45 c0          	lea    -0x40(%rbp),%rax
  401320:	48 83 c0 48          	add    $0x48,%rax
  401324:	48 8b 00             	mov    (%rax),%rax
  401327:	48 89 c6             	mov    %rax,%rsi
  40132a:	48 8d 05 95 0d 00 00 	lea    0xd95(%rip),%rax        # 4020c6 <_IO_stdin_used+0xc6>
  401331:	48 89 c7             	mov    %rax,%rdi
  401334:	b8 00 00 00 00       	mov    $0x0,%eax
  401339:	e8 72 fd ff ff       	call   4010b0 <printf@plt>
  40133e:	b8 00 00 00 00       	mov    $0x0,%eax
  401343:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  401347:	64 48 2b 14 25 28 00 	sub    %fs:0x28,%rdx
  40134e:	00 00 
  401350:	74 05                	je     401357 <main+0x198>
  401352:	e8 39 fd ff ff       	call   401090 <__stack_chk_fail@plt>
  401357:	c9                   	leave
  401358:	c3                   	ret

Disassembly of section .fini:

000000000040135c <_fini>:
  40135c:	f3 0f 1e fa          	endbr64
  401360:	48 83 ec 08          	sub    $0x8,%rsp
  401364:	48 83 c4 08          	add    $0x8,%rsp
  401368:	c3                   	ret
