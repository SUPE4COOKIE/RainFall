# Problèmes résiduels dans les walkthroughs

## level1 — Offset EIP non expliqué

Le walkthrough dit "buffer de 76 octets" et "offset à 76". En théorie, un buffer de 76 octets suivi d'un EBP sauvegardé (4 octets) devrait donner un offset de 80 avant EIP. Ici l'offset est empiriquement 76 (confirmé par `dmesg`), ce qui suggère que le compilateur n'a pas sauvegardé EBP entre le buffer et l'adresse de retour. Ce comportement n'est pas expliqué dans le walkthrough.

---

---



