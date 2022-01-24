# README #

本專案主要提供這些 Ansible Playbooks:

1. 依據 CVE/Advisory 來更新套件
  - cve_id: 字串，指定的 CVE 編號，例如 CVE-2020-13632
  - advisory_id: 字串，指定的 Advisory 編號，例如 RHBA-2020:5090
2. 依據套件來進行安裝或更新
  - packages: 字串，套件名稱，以逗號分隔，例如 "nginx,chrony"


