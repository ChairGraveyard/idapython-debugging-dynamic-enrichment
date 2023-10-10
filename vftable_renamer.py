import idaapi
import idautils
import idc

# needed for regexp [a3e1bcd6]
import re


# Ask for a prefix that will be added to subs in the specified range
func_prefix = idc.AskStr("MyClass::", "Enter a prefix that will be added to subs")

if (func_prefix == "MyClass::") or not func_prefix:
    quit()

start_addr = idc.SelStart()
end_addr = idc.SelEnd()
# TODO: 'ask' for it
skip_bad_prefixes = True

#start = idc.SelStart()
#end = idc.SelEnd()

# print hex(start), hex(end)

# while start < end: 
#     # print hex(idc.Qword(start))
#     print hex(start)
#     start = idc.NextAddr(start)

# quit()

# [[441b119f]]
# Asks for a start address of a vftable. Function names in this range (start_addr-end_addr) will be renamed.
# 
# ---------------------------------------------------------------------------------------------
# Help for: idc.AskAddr
# Shows a popup window and asks for an address, returns BADADDR in case it entered incorrectly
# arg0 - the default address that will be shown in the popup (integer)
# arg1 - message to be shown in the popup
# ---------------------------------------------------------------------------------------------
# Help for: int('0x0000000142C79E00', 16)
# Converts a HEX string into integer
# arg1 - string to be converted to an integer
# arg2 - base of the number, passed as a string in the first argument (16 = HEX)
# start_addr = idc.AskAddr(int('0x0000000142C79DF8', 16), "Enter a start address of a vftable")

# the same as [441b119f]
# end_addr = idc.AskAddr(0, "Enter an end address of a vftable")

# bytes_str = idc.GetManyBytes(start_addr, 4, False)


# For each address in specified range (vftable) add a prefix to functions
# --------------------------------------------------------------------------------------------
# range help:
# arg1 start address of the vftable (for renaming functions)
# arg2 end address of the vftable (for renaming functions)
# 8 is the length of a pointer for x64 architecture
#   (64 bits)/(8 bits) == 8 bytes
# +1 needed for including the last addr
#---------------------------------------------------------------------------------------------
# Example:
# for i in range(int('0x0000000142C79DF8', 16), int('0x0000000142C79E10', 16) + 1, 8):
# ...  format(i, '#04x')
# ...
# '0x142c79df8'
# '0x142c79e00'
# '0x142c79e08'
# '0x142c79e10'
for i in range(start_addr, end_addr + 1, 8):
    # Read an offset of a function in vftable. Needed to get function name later
    func_addr = idc.Qword(i)

    # 
    func_name = idc.GetFunctionName(func_addr)

    # [[a3e1bcd6]]
    # Match default names for subs\nullsubs
    # ----------------------------------------------------------------------------------------
    # Examples of default names:
    #   nullsub_4774
    #   nullsub_56
    #   sub_14006AD20
    # ----------------------------------------------------------------------------------------
    # Example 1:
    # result = re.findall(r'^sub_[0-9a-fA-F]{9,9}$','sub_1401529F0')
    # len(result)
    #
    # Output:
    # ['sub_1401529F0']
    # 1
    default_func_name_matches = re.findall(r'^(sub_[0-9a-fA-F]{9,9}$|nullsub_[0-9a-fA-F]{2,4})', func_name)

    # exclude __purecall for renaming
    exclude_func_name_matches = re.findall(r'purecall', func_name)

    # Find already renamed functions. Sometimes you name then for wrong base class.
    # Example:
    # wrongParentBase_sub_1401536C0
    sub_index = func_name.find('nullsub_')
    if sub_index == -1:
        sub_index = func_name.find('sub_')

    is_default_func_name = len(default_func_name_matches) > 0
    is_func_name_to_exclude = len(exclude_func_name_matches) > 0
    has_prefix = sub_index > -1

    if (
        not is_default_func_name
        and not is_func_name_to_exclude
        and sub_index > 0
        and skip_bad_prefixes
        or not is_default_func_name
        and is_func_name_to_exclude
        or not is_default_func_name
        and sub_index <= 0
    ):
        continue
    elif not is_default_func_name:
        func_name = func_name[sub_index:]
    new_name = func_prefix + func_name
    idc.MakeName(func_addr, new_name)


#
# print("Function name is:")
# print(func_name)
# print hex(start_addr)
# print hex(end_addr)
