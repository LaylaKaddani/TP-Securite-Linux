# TP-Securite-Linux

# Travaux Pratiques — Administrations et Hardening Linux

Ce dépôt rassemble les travaux pratiques d'administration système sécurisée et de durcissement (hardening) réalisés sous Debian 12 (Bookworm) et AlmaLinux 9.

L'objectif est de documenter la mise en œuvre de contrôles de sécurité système, du principe de moindre privilège au confinement applicatif.

## Sommaire des modules

| Module | Objectifs techniques | Writeup | 
| :--- | :--- | :---: | 
| **01. Linux Authentification** | Sudoers, PAM pwquality, PAM limits, Scripting d'audit Bash | [TP 1](./01-linux-authentification/README.md) | 
| **02. Linux Sécurisation** | Hardening Kernel, Sysctl, Services systemd, Logs (rsyslog/journald) | [TP 2](./02-linux-securisation/README.md) | 
| **03. Droits et Confinement** | SUID, Sticky Bit, ACLs POSIX, Profils AppArmor, SELinux | [TP 3](./03-droits-confinement/README.md) |
| **04. Détection d'Intrusion** | Contrôle d'intégrité (dpkg/rpm), AIDE, OSSEC (Client/Serveur) | [TP 4](./04-hids/README.md) | 

## Environnement d'expérimentation

- **OS :** Debian 12 (Bookworm) / AlmaLinux 9
- **Compétences :** Administration système Linux, IAM, Hardening, SecOps
