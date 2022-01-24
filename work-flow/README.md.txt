# workflow-simple

用來測試 tower workflow 用的。

裡面主要有三個 playbook
1. main.yml: 裡面會依據變數 expect_result 來決定要成功或失敗
2. success.yml: 當 main.yml 成功時，要執行的 playbook
3. failure.yml: 當 main.yml 失敗時，要執行的 playbook

在 tower 裡會設置三個 job template
1. flow-main: playbook 設置為 main.yml
2. flow-success: playbook 設置為 success.yml
3. flow-failure: playbook 設置為 failure.yml