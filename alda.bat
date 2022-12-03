cd C:\Users\HP\PycharmProjects\BlockChain\
start cmd.exe @cmd /k python agent.py
for /L %%a in (1,1,2) do (
start cmd.exe @cmd /k python agent.py
)
done




