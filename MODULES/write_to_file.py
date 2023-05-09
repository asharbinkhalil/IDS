def add_to_current(log):
    with open('./LOGS/current.txt', 'a') as file:
        file.write(log) 
        file.close()  
def add_to_logs(log):
    with open('./LOGS/logs.txt', 'a') as file:
        file.write(log)
        file.close()