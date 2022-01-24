# 設定檔案內容比對與套用

主要包含兩個部份：

1. 依據 files/filelist.txt 裡的檔名，再以 files 內的同名檔案跟遠端機器上對應的檔案做比較 (SHA256)，若內容相異，則告知相異。
2. 依據 files/filelist.txt 裡的檔名，再以 files 內的同名檔案跟遠端機器上對應的檔案做比較 (SHA256)，若內容相異，則覆蓋。

## filelist.txt 格式

檔案路徑(含檔名)

例如：
```
/etc/motd
/etc/sysctl.d/99custom.conf
```

## 使用前注意

範例使用 '-i localhost, -c local' 是為了方便在本機測試，實機測試時，要使用

```
-i your_host --become
```

## 使用：compoare.yml

進行比對

```
ansible-playbook -i localhost, -c local compare.yml
```

輸出結果可以找 [Display output]
```
TASK [Display output] *********************************************************************************************************
ok: [localhost] => {
    "output": "### Compare Result ###\n[FAIL] /etc/sysctl.d/99custom.conf is not MATCHED.\n[FAIL] /etc/motd is not MATCHED."
}
```

## 使用： overwrite.yml

帶入 files，表示要處理哪些檔案，以 ',' 分隔。
```
ansible-playbook -e files=/etc/motd -i localhost, -c local overwrite.yml
```

若帶入未在 filelist.txt 裡的檔案，會出現錯誤
```
ansible-playbook -e files=/etc/nginx/nginx.conf,/etc/hosts -i localhost, -c local overwrite.yml

# ...
# TASK [Check] ******************************************************************************************************************
# fatal: [localhost]: FAILED! => {"changed": false, "msg": "'/etc/hosts'' is not in filelist.txt"}
# ...
```
