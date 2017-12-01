# evoting
This is the repo for evoting system defualt is to generate 1024 bits long key

key generation:
1. run ./keypair_prime 90000000 to generate prime numbers
2. run ./keypair_generate  -Pfile ./outputprime_90000000_1.txt -O ./outputkey.txt -n 1000100
3. run ./generate_partresult_group.go to generate the partresult.txt
4. run ./generate_ws to generate the final output_ws.txt, it will also verify the correct of the result of the ring signature.


