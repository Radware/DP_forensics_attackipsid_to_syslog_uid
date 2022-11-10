
#read from file
with open('attackipsid_input.txt', 'r') as f:
	attackipsid = f.read().splitlines()

#remove duplicates
attackipsid = list(dict.fromkeys(attackipsid))


for id in attackipsid:
	#if id is not empty
	if id:
		id_first_part_dec = id.split('-')[0]
		id_second_part_dec = id.split('-')[1]
		#convert id_first_part_dec to hex removing 0x
		id_first_part_hex = hex(int(id_first_part_dec))[2:]
		id_second_part_hex = hex(int(id_second_part_dec))[2:]

		if len(id_first_part_dec) == 8 and len(id_second_part_dec) == 10:
			#If the first part of the ID is 8 digits, the second part is 10 digits
			# print('id_first_part_dec is 8, id_second_part_dec is 10')
			
			# create new var id_first_part_hex_prefix which includes only first 3 chars of id_first_part_hex
			id_first_part_hex_prefix = id_first_part_hex[:3]
			
			#remove first 3 chars from id_first_part_hex
			id_first_part_hex = id_first_part_hex[3:]

			#convert id_second_part_dec to hex removing 0x
			id_second_part_hex = '0' + id_first_part_hex_prefix + id_second_part_hex

			#create new string = FFFFFFFF-FFFF-FFFF- + id_first_part_hex + id_second_part_hex
			syslog_id = 'FFFFFFFF-FFFF-FFFF-' + id_first_part_hex + '-' + id_second_part_hex
			print(f'AttackIpsID {id} , syslog ID {syslog_id}')

		elif len(id_first_part_dec) == 7 and len(id_second_part_dec) == 10:
			#If the first part of the ID is 7 digits, the second part is 10 digits
			# print('id_first_part_dec is 7, id_second_part_dec is 10')
			# create new var id_first_part_hex_prefix which includes only first 2 chars of id_first_part_hex
			id_first_part_hex_prefix = id_first_part_hex[:2]
			
			#remove first 2 chars from id_first_part_hex
			id_first_part_hex = id_first_part_hex[2:]

			#convert id_second_part_dec to hex removing 0x
			id_second_part_hex = '00' + id_first_part_hex_prefix + id_second_part_hex

			#create new string = FFFFFFFF-FFFF-FFFF- + id_first_part_hex + id_second_part_hex
			syslog_id = 'FFFFFFFF-FFFF-FFFF-' + id_first_part_hex + '-' + id_second_part_hex
			print(f'AttackIpsID {id} , syslog ID {syslog_id}')

		elif len(id_first_part_dec) == 6 and len(id_second_part_dec) == 9:
			#If the first part of the ID is 6 digits, the second part is 10 digits
			# print('id_first_part_dec is 6, id_second_part_dec is 10')
			# create new var id_first_part_hex_prefix which includes only first 1 chars of id_first_part_hex
			id_first_part_hex_prefix = id_first_part_hex[:1]
			
			#remove first 1 chars from id_first_part_hex
			id_first_part_hex = id_first_part_hex[1:]

			#convert id_second_part_dec to hex removing 0x
			id_second_part_hex = '0000' + id_first_part_hex_prefix + id_second_part_hex

			#create new string = FFFFFFFF-FFFF-FFFF- + id_first_part_hex + id_second_part_hex
			syslog_id = 'FFFFFFFF-FFFF-FFFF-' + id_first_part_hex + '-' + id_second_part_hex

			print(f'AttackIpsID {id} , syslog ID {syslog_id}, This conversion needs to be tested further and validated!!!')
		
		
		
		else:
			print(f'ID: {id} does not match any condition for conversion')






