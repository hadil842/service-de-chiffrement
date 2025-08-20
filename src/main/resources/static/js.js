const usernameinput=document.getElementById('username');
const passwordinput=document.getElementById('password');
const message=document.getElementById('messagarea');
const datainput=document.getElementById('data');
let secretkey;
let jwt;
 const operations = window.crypto.subtle;
async function login(){
    let name=usernameinput.value;
    let pass=passwordinput.value;
    message.textContent='';
    let param={
            username:name,
            password:pass
            }
    try{
    const url='http://localhost:8080/login';
    //send param to the api
    let reponse =await fetch(url,{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify(param)
            });
    //error fetch
    if(!reponse.ok){
        let errortext=await reponse.text();
        console.log('Fetch error:', errortext);
        switch(reponse.status){
             case 401:
                message.textContent='Unautorized :please log in again';
                break;
             case 403:
                message.textContent='Invalid user';
                break;
             default:
                message.textContent='Error';
                }
    //fetch succeded
    }else{
            let responsedata=await reponse.json();
            message.textContent=`${JSON.stringify(responsedata)}`;
            //message.textContent='Login successfully';
            let privateKeyBuffer=converttoarray("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCn5TaMldXHYK9adPAfvz/5P6OBgJI4RseKbHYw/C+Enhk6suBdgQPcWCI5BHWkSXmn283rI6id/kowZYh7CA/IN1dUOGnF1d+p41w1mluxvPXX5bGeg85BeEn1CEtyp7S19BY9abpm8IPWYjdeeqNsmD9n1OP1FTtK/hsaOPTDdSSrCVUm3wCDFU/LBmioF95CuwkBW//1p885Dn4Ioa5EgQrwVNWEHuTXDmA9YidM9vbEGZB5bAWth3RoeOU1GAZ+79EVO4vUVe28xthjcvCoiBtf0+k0bp+1nWy9iol+c+rUkATzgwlHDYNbpX3uFYfDCd+XqxYB/kcX1y/ML+BXAgMBAAECggEAQHVeyQCpj59OE1N78SRS4lWNZ6W9/X8nErzrb4kSkT7FfuS4AQ4MNmdb1DojFEzlOQ3Jc/I/xVCgmQ4SJPIGZR7iF0KFUV/4O9g/SZEWjRl35UiZNbtyz23oLvvdQ4qhdY3dj/xshSLn6sHQciRxY7rb9PgmAK0DE5qVOy8MwZEzYJSKYRPpO//Qa9Nceuq7ZYzYC3tyqZVWpCYBMc7BvW2dl5FtIjpfASQGys+7p4zOSY9laGrl+x/UgrOTN20OKvjUMmmk+WaG2TXeR9IjJaJvis4LgqxAYAL3W8SONouj0oxJBOvjaYoMDsF7a1D5xSybLm/C7ye4pTKAoNns+QKBgQDC2rzrZSWzxxUwqVAIA+IYUMw2esyjo6Arb1VxoszzZGZUhXgpKaNa9TH83WDC9aGjBI7/yS1pHhqCQX68P3q7rgflNs3ATvIb+xtP4d11kDcKwjX1xRJTY4uD9xSRTBOCgNwd13JSHgFYHcB6D5UUagaHRhGA0ev2FdOpjJbFgwKBgQDclMS6CYhGpAoBxZWxqHDC+z13CyiwQnFKDefWXPBg7mAiAB8TLiMW6mg6FBacde72oK9wFMaEpmbGEi3/8jQFZTLvoYathre5ycL6+31/+yaTEgRnmZESmR1nFXoHgiLETWS6uflfL/31ksuL7zl+LpeDJIcPuuKr4H9eslcVnQKBgDwI6Owd3d/mFsFHaUEO8TpMqp6edy5z24WGZ+z7G+phpKWl+b+09H+xzBT8oDNxOrvfS6/DbBpXDBPV2hZl+IqatBQLLplxuWall2SlUnZGWK8X50gxz9Ohd/rQxaV+qwQqb6dCGhby57cec48n/easRBapn/rwsqK/VteGWW3BAoGAAoqINah0dHPhVaHkFpbdLbHdRGjRgC5TxcmhORv6/PLiEqIzuXHXn6T1rG2c0RKevSKewsjKfK66EmAVPZSZutIuowoWVhtuNGq5n1CUYowPJrSXbmYbgL5Y014w+LMsGVzW4zvPPqR75X9abvNDk0uQHUencqvxfo9oiDu/uxUCgYAGNQ/aNHEsjGq4UBBqKcVsrInootmBZ2D3e04ii/k0XpiMw/ct+M3q3TF241PuTtSaW7E8gN8pea/OiVAGO8S1ORHqDu03aUvdB2FfkrLzJcCDOGj72FDhMc+dFEKkX+3BxF2qgwxGOydBvzate2g1M27q4tWCDt2Z8cNLZzL6tw==");
            // get the private key
            let privkey;
            try {
                privkey = await operations.importKey(
                    "pkcs8",
                    privateKeyBuffer, 
                    {
                        name: "RSA-OAEP",
                        hash: "SHA-1"
                    },
                    true,
                    ["decrypt"]
                );
                console.log("Private key imported successfully.");
            } catch (error) {
                console.error("Error importing private key:", error);
            }
            // decrypt the secret key
            let secretkeybuffer = converttoarray(responsedata.stmkey);
            jwt=responsedata.jwt;
            let decryptedSecretKey;
            try{
            decryptedSecretKey = await operations.decrypt(
                { name: "RSA-OAEP" }, 
                privkey,
                secretkeybuffer
            );
            console.log("Secret key decrypted successfully:");
            }catch(error){
                console.error('Decryption error:',error);
            };
            //import the secret key 
            try{
            secretkey=await operations.importKey(
                 "raw",
                 decryptedSecretKey,
                 "AES-GCM",
                 true,
                 ["decrypt","encrypt"]
            );
            console.log("Secretkey imported succesfully");
        }catch(error){
              console.log("Importation Error:",error);
        }  
    }
    } catch (error) {
        console.error('Fetch error:', error);
    }
}
async function senddata() {
    let data=datainput.value;
    const url='http://localhost:8080/send-data';
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    //prepare data
    const encoder = new TextEncoder();
    const encodedBytes = encoder.encode(data);
    //encryption
    const encrypteddata = await operations.encrypt(
    { name: "AES-GCM", iv },
    secretkey,
    encodedBytes
  );
  //prepare data to send
    const ivbase64=arraybuffertobase64(iv.buffer);
    const encrybase64=arraybuffertobase64(encrypteddata);
    const datatosend={
        iv:ivbase64,
        ciphertext:encrybase64
    }
    //send the data
    let reponse =await fetch(url,{
            method:'POST',
            headers:{'Content-Type':'application/json','Authorization':`Bearer ${jwt}`},
            body:JSON.stringify(datatosend)
            });
    if(!reponse.ok){
        let errortext=await reponse.text();
        console.log('Fetch error:', errortext);
    }else{
        console.log("Operation succeeded");
    }
}   
function converttoarray(base64){
      const binary=window.atob(base64.trim());//to encode to base64 we use btoa
      const len=binary.length;
      const bytes=new Uint8Array(len);
      for(let i=0;i<len;i++){
        bytes[i]=binary.charCodeAt(i);
      }
      return bytes.buffer;
}
function arraybuffertobase64(buffer){
    let binary='';
    const bytes=new Uint8Array(buffer);
    const len =bytes.byteLength;
    for(let i=0;i<len;i++){
        binary+=String.fromCharCode(bytes[i]);
      }
      return window.btoa(binary);

}