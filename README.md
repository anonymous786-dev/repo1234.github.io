<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Decrypt encrypted images</title>
    <style>
        body {
            max-width: 900px;
            margin: 32px auto;
            padding: 0 20px;
            font: 16px/1.5 system-ui, sans-serif;
            color: #202124;
        }

        img[encrypted-img="true"] {
            display: block;
            max-width: 100%;
            height: auto;
            margin: 20px 0;
        }

        #status {
            min-height: 1.5em;
        }
    </style>
</head>
<body>
    <h1>Decrypt encrypted images</h1>
    <p>Encrypted images are fetched and decrypted automatically. Serve this page and local images over HTTP/HTTPS; remote image servers must allow CORS for this page.</p>
    <p id="status" role="status" aria-live="polite">Waiting for the page to load.</p>
    <img src="turkishi.png" encrypted-img="true" alt="Encrypted image example">

 <img src="turkishii.png" encrypted-img="true" alt="Encrypted image example">


 <img src="11.jpg.png" encrypted-img="true" alt="Encrypted image example">




 
</body>
</html>
