
#read from file
with open('attackipsid_input.txt', 'r') as f:
	attackipsid = f.read().splitlines()

#remove duplicates
attackipsid = list(dict.fromkeys(attackipsid))


for id in attackipsid:
	id_first_part_dec = id.split('-')[0]
	id_second_part_dec = id.split('-')[1]
	#convert id_first_part_dec to hex removing 0x
	id_first_part_hex = hex(int(id_first_part_dec))[2:]
	
	# create new var id_first_part_hex_prefix which includes only first 3 chars of id_first_part_hex
	id_first_part_hex_prefix = id_first_part_hex[:3]
	
	#remove first 3 chars from id_first_part_hex
	id_first_part_hex = id_first_part_hex[3:]

	#convert id_second_part_dec to hex removing 0x
	id_second_part_hex = hex(int(id_second_part_dec))[2:]

	id_second_part_hex = '0' + id_first_part_hex_prefix + id_second_part_hex

	#create new string = FFFFFFFF-FFFF-FFFF- + id_first_part_hex + id_second_part_hex
	syslog_id = 'FFFFFFFF-FFFF-FFFF-' + id_first_part_hex + '-' + id_second_part_hex

	print(f'AttackIpsID {id} , syslog ID {syslog_id}')




