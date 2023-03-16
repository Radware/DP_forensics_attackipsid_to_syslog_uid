# Python 2.7
# This script converts AttackIpsID to Syslog ID and vice versa
from collections import OrderedDict

def syslog_id_to_attackipsid(syslog_id):
     # This function converts syslog ID to AttackIpsID

    # if id starts with FFFFFFFF-FFFF-FFFF strip it
    if syslog_id.startswith('FFFFFFFF-FFFF-FFFF-'):
        syslog_id_stripped = syslog_id[19:]

        syslog_id_first_part_hex = syslog_id_stripped.split('-')[0]
        syslog_id_second_part_hex = syslog_id_stripped.split('-')[1]
        
        # get first 4 digits from second part and the reminder
        syslog_id_second_part_hex_prefix = syslog_id_second_part_hex[:4]
        syslog_id_second_part_hex_reminder = syslog_id_second_part_hex[4:]

        # check syslog_id_second_part_hex_prefix value and if there any 0s in the beginning, strip them
        if syslog_id_second_part_hex_prefix.startswith('0'):
            syslog_id_second_part_hex_prefix = syslog_id_second_part_hex_prefix.lstrip('0')

        # add syslog_id_second_part_hex_prefix before syslog_id_first_part_hex
        syslog_id_first_part_hex = syslog_id_second_part_hex_prefix + syslog_id_first_part_hex

        # convert syslog_id_first_part hex to decimal
        syslog_id_first_part_dec = int(syslog_id_first_part_hex, 16)

        # convert syslog_id_second_part reminder hex to decimal
        syslog_id_second_part_dec = int(syslog_id_second_part_hex_reminder, 16)

        attackipsid = str(syslog_id_first_part_dec) + '-' + str(syslog_id_second_part_dec)

        print "syslog ID "+ str(syslog_id) + " , AttackIpsID " + str(attackipsid)    

def attackipsid_to_syslog_id(id):
    # This function converts AttackIpsID to Syslog ID

    id_first_part_dec = int(id.split('-')[0])
    id_second_part_dec = int(id.split('-')[1])

    # convert id_first_part_dec to hex removing 0x and the 'L' when the number type is Long
    id_first_part_hex = hex(int(id_first_part_dec))[2:].replace('L','')
    id_second_part_hex = hex(int(id_second_part_dec))[2:].replace('L','')

    ###################### Second part padding ######################
    if id_second_part_dec >= 16777216 and id_second_part_dec <= 268435455:
        # If the second prt of the ID is 8-9 decimal digits which generates HEX of 7 chars, pad second part with one zero
        id_second_part_hex = '0' + id_second_part_hex

    if id_second_part_dec >= 1048576 and id_second_part_dec <= 16777215:
        # If the second prt of the ID is 7-8 decimal digits which generates HEX of 6 chars, pad second part with two zeros
        id_second_part_hex = '00' + id_second_part_hex

    if id_second_part_dec >= 65536 and id_second_part_dec <= 1048575:
        # If the second prt of the ID is 5-7 decimal digits which generates HEX of 5 chars, pad second part with three zeros
        id_second_part_hex = '000' + id_second_part_hex

    if id_second_part_dec >= 4096 and id_second_part_dec <= 65535:
        # If the second prt of the ID is 4-5 decimal digits which generates HEX of 4 chars, pad second part with four zeros
        id_second_part_hex = '0000' + id_second_part_hex

    if id_second_part_dec >= 256 and id_second_part_dec <= 4095:
        # If the second prt of the ID is 3-4 decimal digits which generates HEX of 3 chars, pad second part with five zeros
        id_second_part_hex = '00000' + id_second_part_hex

    if id_second_part_dec >= 16 and id_second_part_dec <= 255:
        # If the second prt of the ID is 2-3 decimal digits which generates HEX of 2 chars, pad second part with six zeros
        id_second_part_hex = '000000' + id_second_part_hex

    if id_second_part_dec >= 0 and id_second_part_dec <= 15:
        # If the second prt of the ID is 0-2 decimal digits which generates HEX of 1 chars, pad second part with seven zeros
        id_second_part_hex = '0000000' + id_second_part_hex

    ###################### First part and Syslog construction ######################

    elif id_first_part_dec >= 0 and id_first_part_dec <= 15:
        # If the first prt of the ID is 0-2 digits which generates HEX of 1 chars
        id_first_part_hex = '000' + id_first_part_hex
        id_second_part_hex = '0000' + id_second_part_hex

        # create new string = FFFFFFFF-FFFF-FFFF- + id_first_part_hex + id_second_part_hex
        syslog_id = 'FFFFFFFF-FFFF-FFFF-' + id_first_part_hex + '-' + id_second_part_hex
        print "AttackIpsID " + id + " , syslog ID " + syslog_id

    elif id_first_part_dec >= 16 and id_first_part_dec <= 255:
        # If the first prt of the ID is 2-3 digits which generates HEX of 2 chars
        id_first_part_hex = '00' + id_first_part_hex
        id_second_part_hex = '0000' + id_second_part_hex

        # create new string = FFFFFFFF-FFFF-FFFF- + id_first_part_hex + id_second_part_hex
        syslog_id = 'FFFFFFFF-FFFF-FFFF-' + id_first_part_hex + '-' + id_second_part_hex
        print "AttackIpsID " + id + " , syslog ID " + syslog_id

    elif id_first_part_dec >= 256 and id_first_part_dec <= 4095:
        # If the first prt of the ID is 3-4 digits which generates HEX of 3 chars
        id_first_part_hex = '0' + id_first_part_hex
        id_second_part_hex = '0000' + id_second_part_hex

        # create new string = FFFFFFFF-FFFF-FFFF- + id_first_part_hex + id_second_part_hex
        syslog_id = 'FFFFFFFF-FFFF-FFFF-' + id_first_part_hex + '-' + id_second_part_hex
        print "AttackIpsID " + id + " , syslog ID " + syslog_id

    elif id_first_part_dec >= 4096 and id_first_part_dec <= 65535:
        # If the first prt of the ID is 4-5 digits which generates HEX of 4 chars

        id_second_part_hex = '0000' + id_second_part_hex

        # create new string = FFFFFFFF-FFFF-FFFF- + id_first_part_hex + id_second_part_hex
        syslog_id = 'FFFFFFFF-FFFF-FFFF-' + id_first_part_hex + '-' + id_second_part_hex
        print "AttackIpsID " + id + " , syslog ID " + syslog_id

    elif id_first_part_dec >= 65536 and id_first_part_dec <= 1048575:
        # If the first prt of the ID is 5-7 digits which generates HEX of 5 chars, move extra 1 char to second part and pad it with three zeros

        # create new var id_first_part_hex_prefix which includes only first 1 char of id_first_part_hex
        id_first_part_hex_prefix = id_first_part_hex[:1]

        # remove first 1 chars from id_first_part_hex
        id_first_part_hex = id_first_part_hex[1:]

        id_second_part_hex = '000' + id_first_part_hex_prefix + id_second_part_hex

        # create new string = FFFFFFFF-FFFF-FFFF- + id_first_part_hex + id_second_part_hex
        syslog_id = 'FFFFFFFF-FFFF-FFFF-' + id_first_part_hex + '-' + id_second_part_hex
        print "AttackIpsID " + id + " , syslog ID " + syslog_id

    elif id_first_part_dec >= 1048576 and id_first_part_dec <= 16777215:
        # If the first prt of the ID is 7-8 digits which generates HEX of 6 chars, move extra 2 chars to second part and pad it with two zeros

        # create new var id_first_part_hex_prefix which includes only first 2 chars of id_first_part_hex
        id_first_part_hex_prefix = id_first_part_hex[:2]

        # remove first 2 chars from id_first_part_hex
        id_first_part_hex = id_first_part_hex[2:]

        id_second_part_hex = '00' + id_first_part_hex_prefix + id_second_part_hex

        # create new string = FFFFFFFF-FFFF-FFFF- + id_first_part_hex + id_second_part_hex
        syslog_id = 'FFFFFFFF-FFFF-FFFF-' + id_first_part_hex + '-' + id_second_part_hex
        print "AttackIpsID " + id + " , syslog ID " + syslog_id

    elif id_first_part_dec >= 16777216 and id_first_part_dec <= 268435455:
        # If the first prt of the ID is 8-9 digits which generates HEX of 7 chars, move extra 3 chars to second part and pad it with one zero

        # create new var id_first_part_hex_prefix which includes only first 3 chars of id_first_part_hex
        id_first_part_hex_prefix = id_first_part_hex[:3]

        # remove first 3 chars from id_first_part_hex
        id_first_part_hex = id_first_part_hex[3:]

        id_second_part_hex = '0' + id_first_part_hex_prefix + id_second_part_hex

        # create new string = FFFFFFFF-FFFF-FFFF- + id_first_part_hex + id_second_part_hex
        syslog_id = 'FFFFFFFF-FFFF-FFFF-' + id_first_part_hex + '-' + id_second_part_hex
        print "AttackIpsID " + id + " , syslog ID " + syslog_id

    elif id_first_part_dec >= 268435456 and id_first_part_dec <= 4294967295:
        # If the first prt of the ID is 9-10 digits which generates HEX of 8 chars, move extra 4 chars to second part and do not pad it

        # create new var id_first_part_hex_prefix which includes only first 4 chars of id_first_part_hex
        id_first_part_hex_prefix = id_first_part_hex[:4]

        # remove first 4 chars from id_first_part_hex
        id_first_part_hex = id_first_part_hex[4:]

        id_second_part_hex = id_first_part_hex_prefix + id_second_part_hex

        # create new string = FFFFFFFF-FFFF-FFFF- + id_first_part_hex + id_second_part_hex
        syslog_id = 'FFFFFFFF-FFFF-FFFF-' + id_first_part_hex + '-' + id_second_part_hex
        print "AttackIpsID " + id + " , syslog ID " + syslog_id

    else:
        print "AttackIpsID " + id + " does not match any condition for conversion"

def main():

    # read from file
    with open('id_input.txt', 'r') as f:
        id_input = f.read().splitlines()

    # remove duplicates
    id_list = list(OrderedDict.fromkeys(id_input))

    print "Attackipsid to Syslogid/SyslogID to Attackipsid v2.0 - by Egor Egorov"
    print "----------------------------------------------------------"


    for id in id_list:
        # if id is not empty
        if id:
            if id.startswith('FFFFFFFF-FFFF-FFFF-'):
                syslog_id_to_attackipsid(id)

            else:
                attackipsid_to_syslog_id(id)

if __name__ == '__main__':
    main()
