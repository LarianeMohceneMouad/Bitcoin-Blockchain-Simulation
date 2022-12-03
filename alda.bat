cd C:\Users\HP\PycharmProjects\BlockChain\
start cmd.exe @cmd /k python p2p_boot_stable_test.py
for /L %%a in (1,1,2) do (
start cmd.exe @cmd /k python p2p_agent_stabe_test.py
)
done




