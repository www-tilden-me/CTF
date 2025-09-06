
vuln:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 c1 2f 00 00 	mov    0x2fc1(%rip),%rax        # 3fd0 <__gmon_start__@Base>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	ret

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 ca 2f 00 00    	push   0x2fca(%rip)        # 3ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 cc 2f 00 00    	jmp    *0x2fcc(%rip)        # 3ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nopl   0x0(%rax)
    1030:	f3 0f 1e fa          	endbr64
    1034:	68 00 00 00 00       	push   $0x0
    1039:	e9 e2 ff ff ff       	jmp    1020 <_init+0x20>
    103e:	66 90                	xchg   %ax,%ax
    1040:	f3 0f 1e fa          	endbr64
    1044:	68 01 00 00 00       	push   $0x1
    1049:	e9 d2 ff ff ff       	jmp    1020 <_init+0x20>
    104e:	66 90                	xchg   %ax,%ax
    1050:	f3 0f 1e fa          	endbr64
    1054:	68 02 00 00 00       	push   $0x2
    1059:	e9 c2 ff ff ff       	jmp    1020 <_init+0x20>
    105e:	66 90                	xchg   %ax,%ax
    1060:	f3 0f 1e fa          	endbr64
    1064:	68 03 00 00 00       	push   $0x3
    1069:	e9 b2 ff ff ff       	jmp    1020 <_init+0x20>
    106e:	66 90                	xchg   %ax,%ax
    1070:	f3 0f 1e fa          	endbr64
    1074:	68 04 00 00 00       	push   $0x4
    1079:	e9 a2 ff ff ff       	jmp    1020 <_init+0x20>
    107e:	66 90                	xchg   %ax,%ax
    1080:	f3 0f 1e fa          	endbr64
    1084:	68 05 00 00 00       	push   $0x5
    1089:	e9 92 ff ff ff       	jmp    1020 <_init+0x20>
    108e:	66 90                	xchg   %ax,%ax

Disassembly of section .plt.got:

0000000000001090 <__cxa_finalize@plt>:
    1090:	f3 0f 1e fa          	endbr64
    1094:	ff 25 46 2f 00 00    	jmp    *0x2f46(%rip)        # 3fe0 <__cxa_finalize@GLIBC_2.2.5>
    109a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

00000000000010a0 <puts@plt>:
    10a0:	f3 0f 1e fa          	endbr64
    10a4:	ff 25 56 2f 00 00    	jmp    *0x2f56(%rip)        # 4000 <puts@GLIBC_2.2.5>
    10aa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000000010b0 <write@plt>:
    10b0:	f3 0f 1e fa          	endbr64
    10b4:	ff 25 4e 2f 00 00    	jmp    *0x2f4e(%rip)        # 4008 <write@GLIBC_2.2.5>
    10ba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000000010c0 <setbuf@plt>:
    10c0:	f3 0f 1e fa          	endbr64
    10c4:	ff 25 46 2f 00 00    	jmp    *0x2f46(%rip)        # 4010 <setbuf@GLIBC_2.2.5>
    10ca:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000000010d0 <fgets@plt>:
    10d0:	f3 0f 1e fa          	endbr64
    10d4:	ff 25 3e 2f 00 00    	jmp    *0x2f3e(%rip)        # 4018 <fgets@GLIBC_2.2.5>
    10da:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000000010e0 <atoll@plt>:
    10e0:	f3 0f 1e fa          	endbr64
    10e4:	ff 25 36 2f 00 00    	jmp    *0x2f36(%rip)        # 4020 <atoll@GLIBC_2.2.5>
    10ea:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000000010f0 <exit@plt>:
    10f0:	f3 0f 1e fa          	endbr64
    10f4:	ff 25 2e 2f 00 00    	jmp    *0x2f2e(%rip)        # 4028 <exit@GLIBC_2.2.5>
    10fa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000001100 <_start>:
    1100:	f3 0f 1e fa          	endbr64
    1104:	31 ed                	xor    %ebp,%ebp
    1106:	49 89 d1             	mov    %rdx,%r9
    1109:	5e                   	pop    %rsi
    110a:	48 89 e2             	mov    %rsp,%rdx
    110d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1111:	50                   	push   %rax
    1112:	54                   	push   %rsp
    1113:	45 31 c0             	xor    %r8d,%r8d
    1116:	31 c9                	xor    %ecx,%ecx
    1118:	48 8d 3d ca 00 00 00 	lea    0xca(%rip),%rdi        # 11e9 <main>
    111f:	ff 15 9b 2e 00 00    	call   *0x2e9b(%rip)        # 3fc0 <__libc_start_main@GLIBC_2.34>
    1125:	f4                   	hlt
    1126:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    112d:	00 00 00 

0000000000001130 <deregister_tm_clones>:
    1130:	48 8d 3d 09 2f 00 00 	lea    0x2f09(%rip),%rdi        # 4040 <stdout@GLIBC_2.2.5>
    1137:	48 8d 05 02 2f 00 00 	lea    0x2f02(%rip),%rax        # 4040 <stdout@GLIBC_2.2.5>
    113e:	48 39 f8             	cmp    %rdi,%rax
    1141:	74 15                	je     1158 <deregister_tm_clones+0x28>
    1143:	48 8b 05 7e 2e 00 00 	mov    0x2e7e(%rip),%rax        # 3fc8 <_ITM_deregisterTMCloneTable@Base>
    114a:	48 85 c0             	test   %rax,%rax
    114d:	74 09                	je     1158 <deregister_tm_clones+0x28>
    114f:	ff e0                	jmp    *%rax
    1151:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1158:	c3                   	ret
    1159:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001160 <register_tm_clones>:
    1160:	48 8d 3d d9 2e 00 00 	lea    0x2ed9(%rip),%rdi        # 4040 <stdout@GLIBC_2.2.5>
    1167:	48 8d 35 d2 2e 00 00 	lea    0x2ed2(%rip),%rsi        # 4040 <stdout@GLIBC_2.2.5>
    116e:	48 29 fe             	sub    %rdi,%rsi
    1171:	48 89 f0             	mov    %rsi,%rax
    1174:	48 c1 ee 3f          	shr    $0x3f,%rsi
    1178:	48 c1 f8 03          	sar    $0x3,%rax
    117c:	48 01 c6             	add    %rax,%rsi
    117f:	48 d1 fe             	sar    $1,%rsi
    1182:	74 14                	je     1198 <register_tm_clones+0x38>
    1184:	48 8b 05 4d 2e 00 00 	mov    0x2e4d(%rip),%rax        # 3fd8 <_ITM_registerTMCloneTable@Base>
    118b:	48 85 c0             	test   %rax,%rax
    118e:	74 08                	je     1198 <register_tm_clones+0x38>
    1190:	ff e0                	jmp    *%rax
    1192:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1198:	c3                   	ret
    1199:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000011a0 <__do_global_dtors_aux>:
    11a0:	f3 0f 1e fa          	endbr64
    11a4:	80 3d bd 2e 00 00 00 	cmpb   $0x0,0x2ebd(%rip)        # 4068 <completed.0>
    11ab:	75 2b                	jne    11d8 <__do_global_dtors_aux+0x38>
    11ad:	55                   	push   %rbp
    11ae:	48 83 3d 2a 2e 00 00 	cmpq   $0x0,0x2e2a(%rip)        # 3fe0 <__cxa_finalize@GLIBC_2.2.5>
    11b5:	00 
    11b6:	48 89 e5             	mov    %rsp,%rbp
    11b9:	74 0c                	je     11c7 <__do_global_dtors_aux+0x27>
    11bb:	48 8b 3d 76 2e 00 00 	mov    0x2e76(%rip),%rdi        # 4038 <__dso_handle>
    11c2:	e8 c9 fe ff ff       	call   1090 <__cxa_finalize@plt>
    11c7:	e8 64 ff ff ff       	call   1130 <deregister_tm_clones>
    11cc:	c6 05 95 2e 00 00 01 	movb   $0x1,0x2e95(%rip)        # 4068 <completed.0>
    11d3:	5d                   	pop    %rbp
    11d4:	c3                   	ret
    11d5:	0f 1f 00             	nopl   (%rax)
    11d8:	c3                   	ret
    11d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000011e0 <frame_dummy>:
    11e0:	f3 0f 1e fa          	endbr64
    11e4:	e9 77 ff ff ff       	jmp    1160 <register_tm_clones>

00000000000011e9 <main>:
    11e9:	f3 0f 1e fa          	endbr64
    11ed:	55                   	push   %rbp
    11ee:	48 89 e5             	mov    %rsp,%rbp
    11f1:	48 83 ec 30          	sub    $0x30,%rsp
    11f5:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    11fc:	00 00 
    11fe:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1202:	31 c0                	xor    %eax,%eax
    1204:	48 8b 05 45 2e 00 00 	mov    0x2e45(%rip),%rax        # 4050 <stdin@GLIBC_2.2.5>
    120b:	be 00 00 00 00       	mov    $0x0,%esi
    1210:	48 89 c7             	mov    %rax,%rdi
    1213:	e8 a8 fe ff ff       	call   10c0 <setbuf@plt>
    1218:	48 8b 05 21 2e 00 00 	mov    0x2e21(%rip),%rax        # 4040 <stdout@GLIBC_2.2.5>
    121f:	be 00 00 00 00       	mov    $0x0,%esi
    1224:	48 89 c7             	mov    %rax,%rdi
    1227:	e8 94 fe ff ff       	call   10c0 <setbuf@plt>
    122c:	48 8b 05 2d 2e 00 00 	mov    0x2e2d(%rip),%rax        # 4060 <stderr@GLIBC_2.2.5>
    1233:	be 00 00 00 00       	mov    $0x0,%esi
    1238:	48 89 c7             	mov    %rax,%rdi
    123b:	e8 80 fe ff ff       	call   10c0 <setbuf@plt>
    1240:	48 8d 05 bd 0d 00 00 	lea    0xdbd(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    1247:	48 89 c7             	mov    %rax,%rdi
    124a:	e8 51 fe ff ff       	call   10a0 <puts@plt>
    124f:	48 8d 05 ca 0d 00 00 	lea    0xdca(%rip),%rax        # 2020 <_IO_stdin_used+0x20>
    1256:	48 89 c7             	mov    %rax,%rdi
    1259:	e8 42 fe ff ff       	call   10a0 <puts@plt>
    125e:	48 8d 05 9f 0d 00 00 	lea    0xd9f(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    1265:	48 89 c7             	mov    %rax,%rdi
    1268:	e8 33 fe ff ff       	call   10a0 <puts@plt>
    126d:	ba 0b 00 00 00       	mov    $0xb,%edx
    1272:	48 8d 05 bf 0d 00 00 	lea    0xdbf(%rip),%rax        # 2038 <_IO_stdin_used+0x38>
    1279:	48 89 c6             	mov    %rax,%rsi
    127c:	bf 01 00 00 00       	mov    $0x1,%edi
    1281:	e8 2a fe ff ff       	call   10b0 <write@plt>
    1286:	48 8b 15 c3 2d 00 00 	mov    0x2dc3(%rip),%rdx        # 4050 <stdin@GLIBC_2.2.5>
    128d:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    1291:	be 10 00 00 00       	mov    $0x10,%esi
    1296:	48 89 c7             	mov    %rax,%rdi
    1299:	e8 32 fe ff ff       	call   10d0 <fgets@plt>
    129e:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    12a2:	48 89 c7             	mov    %rax,%rdi
    12a5:	e8 36 fe ff ff       	call   10e0 <atoll@plt>
    12aa:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    12ae:	ba 0a 00 00 00       	mov    $0xa,%edx
    12b3:	48 8d 05 8a 0d 00 00 	lea    0xd8a(%rip),%rax        # 2044 <_IO_stdin_used+0x44>
    12ba:	48 89 c6             	mov    %rax,%rsi
    12bd:	bf 01 00 00 00       	mov    $0x1,%edi
    12c2:	e8 e9 fd ff ff       	call   10b0 <write@plt>
    12c7:	48 8b 15 82 2d 00 00 	mov    0x2d82(%rip),%rdx        # 4050 <stdin@GLIBC_2.2.5>
    12ce:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    12d2:	be 10 00 00 00       	mov    $0x10,%esi
    12d7:	48 89 c7             	mov    %rax,%rdi
    12da:	e8 f1 fd ff ff       	call   10d0 <fgets@plt>
    12df:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    12e3:	48 89 c7             	mov    %rax,%rdi
    12e6:	e8 f5 fd ff ff       	call   10e0 <atoll@plt>
    12eb:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    12ef:	48 8d 15 73 2d 00 00 	lea    0x2d73(%rip),%rdx        # 4069 <buf>
    12f6:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    12fa:	48 01 d0             	add    %rdx,%rax
    12fd:	48 8b 08             	mov    (%rax),%rcx
    1300:	48 8d 15 62 2d 00 00 	lea    0x2d62(%rip),%rdx        # 4069 <buf>
    1307:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    130b:	48 01 d0             	add    %rdx,%rax
    130e:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    1312:	48 01 ca             	add    %rcx,%rdx
    1315:	48 89 10             	mov    %rdx,(%rax)
    1318:	48 81 7d d0 39 05 00 	cmpq   $0x539,-0x30(%rbp)
    131f:	00 
    1320:	74 05                	je     1327 <main+0x13e>
    1322:	e9 46 ff ff ff       	jmp    126d <main+0x84>
    1327:	90                   	nop
    1328:	bf 00 00 00 00       	mov    $0x0,%edi
    132d:	e8 be fd ff ff       	call   10f0 <exit@plt>

Disassembly of section .fini:

0000000000001334 <_fini>:
    1334:	f3 0f 1e fa          	endbr64
    1338:	48 83 ec 08          	sub    $0x8,%rsp
    133c:	48 83 c4 08          	add    $0x8,%rsp
    1340:	c3                   	ret
