# workflow-simple

�ΨӴ��� tower workflow �Ϊ��C

�̭��D�n���T�� playbook
1. main.yml: �̭��|�̾��ܼ� expect_result �ӨM�w�n���\�Υ���
2. success.yml: �� main.yml ���\�ɡA�n���檺 playbook
3. failure.yml: �� main.yml ���ѮɡA�n���檺 playbook

�b tower �̷|�]�m�T�� job template
1. flow-main: playbook �]�m�� main.yml
2. flow-success: playbook �]�m�� success.yml
3. flow-failure: playbook �]�m�� failure.yml