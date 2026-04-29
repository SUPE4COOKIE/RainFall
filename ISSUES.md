# Problèmes résiduels dans les walkthroughs

## level1 — Offset EIP non expliqué

Le walkthrough dit "buffer de 76 octets" et "offset à 76". En théorie, un buffer de 76 octets suivi d'un EBP sauvegardé (4 octets) devrait donner un offset de 80 avant EIP. Ici l'offset est empiriquement 76 (confirmé par `dmesg`), ce qui suggère que le compilateur n'a pas sauvegardé EBP entre le buffer et l'adresse de retour. Ce comportement n'est pas expliqué dans le walkthrough.

---

---

## level5 — Walkthrough incomplet (reconnu)

Le walkthrough se termine par "Il manque des informations, je sais plus comment on exploit au final."

L'exploit complet consiste à :
1. Trouver l'adresse de la fonction `o()` (qui fait `system("/bin/sh")`) dans le binaire.
2. Utiliser la format string vulnerability de `printf` pour écraser `exit@GOT` (`0x8049838`) avec l'adresse de `o()`.
3. Quand `exit(1)` est appelé, il saute vers `o()` et ouvre un shell.

La fonction `o()` n'est jamais mentionnée dans le walkthrough.

---

## level9 — Layout objet incorrect (README et walkthrough ont le même bug)

Le README et le walkthrough disent :
```
[vtable (4)] [int (4)] [alloc 104]
```

Le code source C++ déclare :
```cpp
char annotation[100];
int value;
```

Le layout réel est donc : `[vtable (4)] [annotation (100)] [int (4)]` — l'ordre `int` et `annotation` est inversé dans les deux documentations. De plus, `annotation` fait 100 octets (pas 104), et `operator.new(0x6c)` = new(108) = vtable(4) + annotation(100) + int(4) confirme cette taille.

La formule de padding `104 - len(shellcode)` dans le README (et le walkthrough) est également fausse de 4 : le padding correct est `100 - len(shellcode)`, le 4 restant étant le champ `int value` qu'on traverse avant d'atteindre la vtable de `obj2`.

---

## bonus0 — Offset EIP incorrect dans le README

- Walkthrough : offset 9 ✓
- README : offset 10 ✗

L'analyse du `dmesg` dans le walkthrough (`segfault at 45444444` avec buf2 = "BBBBCCCCDDDDEEEEFFFF") confirme que l'offset exact est 9 : les bytes [D,D,D,E] = 0x45444444 commencent à buf2[9]. Le README a une erreur. Les deux fonctionnent probablement grâce au NOP sled, mais le walkthrough est correct.

---

