import json
s = input()
data = '{"Ayame": false, "username": "%s"}' % (
    s
)
print(data)
session={}
session['user_data'] = data
user = json.loads(session['user_data'])
print(user['Ayame'])
# name","Ayame":true,"hello":"123
# name", "Ayame" = True, "test" = "123