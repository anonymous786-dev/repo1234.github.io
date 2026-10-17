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




    <script>
        (function (window, document) {
            'use strict';

            var MAGIC_HEADER = [83, 84, 71, 79];
            var KEY_SEED_PATTERN = [0x9A, 0x3F, 0x7E, 0xC1, 0x42, 0x18, 0x8D, 0x55];
            var statusElement = document.getElementById('status');
            var isProcessing = false;

            function setStatus(message) {
                if (statusElement) {
                    statusElement.textContent = message;
                }
            }

            function getKeyPixelOffsets(width, height) {
                var totalPixels = width * height;
                if (!totalPixels) {
                    throw new Error('The image has no readable pixels.');
                }

                var offsets = [];
                for (var i = 0; i < 256; i++) {
                    var seedMod = KEY_SEED_PATTERN[i % KEY_SEED_PATTERN.length];
                    var pixelIndex = (i * 31337 + seedMod * 1009) % totalPixels;
                    offsets.push(pixelIndex * 4 + (i % 3));
                }
                return offsets;
            }

            function loadImageData(blob) {
                return new Promise(function (resolve, reject) {
                    var image = new Image();
                    var objectUrl = URL.createObjectURL(blob);

                    function cleanup() {
                        image.onload = null;
                        image.onerror = null;
                        URL.revokeObjectURL(objectUrl);
                    }

                    image.onload = function () {
                        try {
                            var canvas = document.createElement('canvas');
                            canvas.width = image.naturalWidth;
                            canvas.height = image.naturalHeight;
                            var context = canvas.getContext('2d', { willReadFrequently: true });
                            if (!context) {
                                throw new Error('Could not create a canvas for image processing.');
                            }
                            context.drawImage(image, 0, 0);
                            var pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
                            cleanup();
                            resolve({
                                width: canvas.width,
                                height: canvas.height,
                                data: pixels
                            });
                        } catch (error) {
                            cleanup();
                            reject(new Error('Could not read fetched image pixels: ' + error.message));
                        }
                    };

                    image.onerror = function () {
                        cleanup();
                        reject(new Error('Could not load the encrypted image.'));
                    };

                    image.src = objectUrl;
                });
            }

            function extractPayload(imageData) {
                var data = imageData.data;
                var keyOffsets = getKeyPixelOffsets(imageData.width, imageData.height);
                var keyLookup = Object.create(null);
                var keyBytes = new Uint8Array(32);

                for (var i = 0; i < keyOffsets.length; i++) {
                    var keyPosition = keyOffsets[i];
                    if (keyPosition >= data.length) {
                        throw new Error('The image is too small to contain the encryption key.');
                    }
                    keyLookup[keyPosition] = true;
                    keyBytes[Math.floor(i / 8)] |= (data[keyPosition] & 1) << (7 - (i % 8));
                }

                var payloadLength = Math.floor(
                    (imageData.width * imageData.height * 3 - Object.keys(keyLookup).length) / 8
                );
                var payload = new Uint8Array(payloadLength);
                var payloadBitIndex = 0;

                for (var dataIndex = 0;
                    dataIndex < data.length && payloadBitIndex < payload.length * 8;
                    dataIndex++) {
                    if ((dataIndex + 1) % 4 === 0 || keyLookup[dataIndex]) {
                        continue;
                    }
                    payload[Math.floor(payloadBitIndex / 8)] |=
                        (data[dataIndex] & 1) << (7 - (payloadBitIndex % 8));
                    payloadBitIndex++;
                }

                for (var headerIndex = 0; headerIndex < MAGIC_HEADER.length; headerIndex++) {
                    if (payload[headerIndex] !== MAGIC_HEADER[headerIndex]) {
                        throw new Error('No valid encrypted payload was found in this image.');
                    }
                }
                return { key: keyBytes, payload: payload };
            }

            function parsePayload(payload) {
                var offset = MAGIC_HEADER.length;

                function requireBytes(count) {
                    if (offset + count > payload.length) {
                        throw new Error('The encrypted payload is incomplete or damaged.');
                    }
                }

                requireBytes(2);
                var metadataLength = (payload[offset] << 8) | payload[offset + 1];
                offset += 2;
                requireBytes(metadataLength + 4);

                var metadataBytes = payload.slice(offset, offset + metadataLength);
                offset += metadataLength;
                var metadataText;
                if (typeof TextDecoder !== 'undefined') {
                    metadataText = new TextDecoder('utf-8', { fatal: true }).decode(metadataBytes);
                } else {
                    var metadataBinary = '';
                    for (var i = 0; i < metadataBytes.length; i++) {
                        metadataBinary += String.fromCharCode(metadataBytes[i]);
                    }
                    metadataText = decodeURIComponent(escape(metadataBinary));
                }

                var metadata;
                try {
                    metadata = JSON.parse(metadataText);
                } catch (error) {
                    throw new Error('The encrypted image metadata is invalid.');
                }

                var ciphertextLength = payload[offset] * 0x1000000 +
                    (payload[offset + 1] << 16) +
                    (payload[offset + 2] << 8) +
                    payload[offset + 3];
                offset += 4;
                requireBytes(12 + ciphertextLength);

                var iv = payload.slice(offset, offset + 12);
                offset += 12;
                return {
                    metadata: metadata,
                    iv: iv,
                    ciphertext: payload.slice(offset, offset + ciphertextLength)
                };
            }

            function toBase64(buffer) {
                var bytes = new Uint8Array(buffer);
                var binary = '';
                var chunkSize = 0x8000;
                for (var start = 0; start < bytes.length; start += chunkSize) {
                    var end = Math.min(start + chunkSize, bytes.length);
                    for (var i = start; i < end; i++) {
                        binary += String.fromCharCode(bytes[i]);
                    }
                }
                return window.btoa(binary);
            }

            function getMimeType(metadata) {
                var extension = metadata && metadata.ext
                    ? String(metadata.ext).toLowerCase().replace(/^\./, '')
                    : 'png';
                var mimeTypes = {
                    jpg: 'image/jpeg',
                    jpeg: 'image/jpeg',
                    png: 'image/png',
                    webp: 'image/webp',
                    gif: 'image/gif',
                    bmp: 'image/bmp'
                };
                if (!mimeTypes[extension]) {
                    throw new Error('Unsupported decrypted image format: ' + extension);
                }
                return mimeTypes[extension];
            }

            async function decryptImage(source) {
                if (!window.crypto || !window.crypto.subtle) {
                    throw new Error('Web Crypto is unavailable in this browser.');
                }

                var imageUrl = new URL(source, document.baseURI);
                if (imageUrl.protocol !== 'http:' && imageUrl.protocol !== 'https:') {
                    throw new Error(
                        'Automatic URL loading requires an HTTP or HTTPS page. Browsers block fetching local file:// images; serve this page and image from localhost.'
                    );
                }

                var response;
                try {
                    response = await fetch(imageUrl.href, { mode: 'cors' });
                } catch (error) {
                    throw new Error(
                        'Could not fetch ' + imageUrl.href +
                        '. The image server must allow CORS for this page, or serve the image from the same origin.'
                    );
                }
                if (!response.ok) {
                    throw new Error('Image request failed with HTTP ' + response.status + ': ' + imageUrl.href);
                }

                var imageBlob = await response.blob();
                var contentType = response.headers.get('content-type') || imageBlob.type;
                if (contentType && contentType.toLowerCase().indexOf('text/html') === 0) {
                    throw new Error('The URL returned an HTML page instead of image data: ' + imageUrl.href);
                }
                if (!imageBlob.size) {
                    throw new Error('The URL returned an empty response: ' + imageUrl.href);
                }

                var imageData = await loadImageData(imageBlob);
                var extracted = extractPayload(imageData);
                var parsed = parsePayload(extracted.payload);
                var key = await window.crypto.subtle.importKey(
                    'raw',
                    extracted.key,
                    { name: 'AES-GCM' },
                    false,
                    ['decrypt']
                );
                var plaintext = await window.crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: parsed.iv },
                    key,
                    parsed.ciphertext
                );
                return {
                    buffer: plaintext,
                    mimeType: getMimeType(parsed.metadata),
                    metadata: parsed.metadata
                };
            }

            function findNextImage() {
                var candidates = document.querySelectorAll('img[encrypted-img="true"]');
                for (var i = 0; i < candidates.length; i++) {
                    var state = candidates[i].getAttribute('decrypt');
                    if (state !== 'true' && state !== 'processing' &&
                        state !== 'awaiting-file' && state !== 'failed') {
                        return candidates[i];
                    }
                }
                return null;
            }

            function decryptAndReplace(imgElement, source, sourceName) {
                decryptImage(source).then(function (decrypted) {
                    var base64 = toBase64(decrypted.buffer);
                    var dataUrl = 'data:' + decrypted.mimeType + ';base64,' + base64;

                    return new Promise(function (resolve, reject) {
                        var onLoad = function () {
                            cleanup();
                            imgElement.removeAttribute('encrypted-img');
                            imgElement.setAttribute('decrypt', 'true');
                            imgElement.removeAttribute('data-decrypt-error');
                            setStatus('Decrypted: ' + sourceName);
                            imgElement.dispatchEvent(new CustomEvent('steganocrypt:decrypted', {
                                detail: { metadata: decrypted.metadata, src: imgElement.src },
                                bubbles: true
                            }));
                            resolve();
                        };
                        var onError = function () {
                            cleanup();
                            reject(new Error('Decrypted image data could not be displayed.'));
                        };
                        function cleanup() {
                            imgElement.removeEventListener('load', onLoad);
                            imgElement.removeEventListener('error', onError);
                        }

                        imgElement.addEventListener('load', onLoad);
                        imgElement.addEventListener('error', onError);
                        imgElement.src = dataUrl;
                        base64 = '';
                        dataUrl = '';

                        if (imgElement.complete && imgElement.naturalWidth > 0) {
                            onLoad();
                        }
                    });
                }).catch(function (error) {
                    console.error('[Image decryption error] ' + sourceName, error);
                    imgElement.setAttribute('decrypt', 'failed');
                    imgElement.setAttribute('data-decrypt-error', error.message);
                    setStatus(sourceName + ': ' + error.message);
                }).then(function () {
                    imgElement.removeAttribute('decrypt-processing');
                    isProcessing = false;
                    requestScan();
                });
            }

            function processNextImage() {
                if (isProcessing) {
                    return;
                }

                isProcessing = true;
                var imgElement = findNextImage();

                if (!imgElement) {
                    isProcessing = false;
                    return;
                }

                var source = imgElement.currentSrc || imgElement.src || imgElement.getAttribute('src');
                if (!source) {
                    imgElement.setAttribute('decrypt', 'failed');
                    imgElement.setAttribute('data-decrypt-error', 'Image has no src attribute.');
                    setStatus('An encrypted image has no src attribute.');
                    isProcessing = false;
                    requestScan();
                    return;
                }

                imgElement.setAttribute('decrypt', 'processing');
                var sourceUrl = new URL(source, document.baseURI);
                setStatus('Decrypting ' + sourceUrl.href + '...');
                decryptAndReplace(imgElement, sourceUrl.href, sourceUrl.href);
            }

            function requestScan() {
                if (isProcessing) {
                    return;
                }
                processNextImage();
            }

            if (document.readyState === 'complete') {
                requestScan();
            } else {
                window.addEventListener('load', requestScan, { once: true });
            }

            if (typeof MutationObserver !== 'undefined') {
                var observer = new MutationObserver(function (mutations) {
                    for (var i = 0; i < mutations.length; i++) {
                        var mutation = mutations[i];
                        if (mutation.type === 'attributes' &&
                            mutation.attributeName === 'src' &&
                            mutation.target.getAttribute('decrypt') === 'failed') {
                            mutation.target.removeAttribute('decrypt');
                            mutation.target.removeAttribute('data-decrypt-error');
                        }
                        if (mutation.type === 'attributes' &&
                            mutation.attributeName === 'src' &&
                            mutation.target.getAttribute('decrypt') === 'true') {
                            continue;
                        }
                        requestScan();
                        break;
                    }
                });
                observer.observe(document.documentElement, {
                    childList: true,
                    subtree: true,
                    attributes: true,
                    attributeFilter: ['src', 'encrypted-img']
                });
            }

            window.SteganoCryptSDK = {
                version: '3.0.0',
                scan: requestScan
            };
        })(window, document);
    </script>
</body>
</html>
