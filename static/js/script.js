document.addEventListener('DOMContentLoaded', () => {
    // Fetch files on page load
    fetchFiles();

    // Add event listener to the upload button
    document.getElementById('uploadBtn').addEventListener('click', uploadFile);
});

async function sha256(message) {
    // Encode as UTF-8
    const msgBuffer = new TextEncoder().encode(message);
    // Hash the message
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    // Convert ArrayBuffer to Array
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    // Convert bytes to hex string
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

async function proofOfWork(challenge, difficulty) {
    let nonce = 0;
    const maxNonce = Number.MAX_SAFE_INTEGER;
    while (nonce < maxNonce) {
        const hash = await sha256(challenge + nonce);
        if (hash.startsWith('0'.repeat(difficulty))) {
            return nonce.toString();
        }
        nonce++;
    }
    throw new Error('Proof of Work failed');
}

async function getChallenge() {
    const response = await fetch('/api/get_challenge');
    const data = await response.json();
    return data.challenge;
}

function getCSRFToken() {
    return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
}

async function uploadFile() {
    const fileInput = document.getElementById('fileInput');
    const statusDiv = document.getElementById('status');
    if (fileInput.files.length === 0) {
        statusDiv.textContent = 'Please select a file.';
        statusDiv.style.color = 'red';
        return;
    }
    try {
        statusDiv.textContent = 'Starting Proof of Work...';
        statusDiv.style.color = 'black';
        const difficulty = 4; // Adjust difficulty as needed
        const challenge = await getChallenge();
        const nonce = await proofOfWork(challenge, difficulty);
        statusDiv.textContent = 'Proof of Work completed. Uploading file...';

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('nonce', nonce);

        const csrfToken = getCSRFToken();

        const response = await fetch('/api/upload', {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrfToken
            },
            body: formData
        });

        const result = await response.json();
        if (response.ok) {
            statusDiv.textContent = result.message;
            statusDiv.style.color = 'green';
            fileInput.value = ''; // Clear the file input
            fetchFiles();  // Refresh the file list
        } else {
            statusDiv.textContent = `Error: ${result.message}`;
            statusDiv.style.color = 'red';
        }
    } catch (error) {
        statusDiv.textContent = `Error: ${error.message}`;
        statusDiv.style.color = 'red';
    }
}

async function fetchFiles() {
    const response = await fetch('/files');
    const data = await response.json();
    if (data.status === 'success') {
        const filesTableBody = document.querySelector('#filesTable tbody');
        filesTableBody.innerHTML = '';  // Clear existing rows
        data.files.forEach(file => {
            const row = document.createElement('tr');

            const filenameCell = document.createElement('td');
            filenameCell.textContent = file.filename;

            const uploadTimeCell = document.createElement('td');
            uploadTimeCell.textContent = file.upload_time;

            const actionsCell = document.createElement('td');

            // Download button
            const downloadBtn = document.createElement('button');
            downloadBtn.textContent = 'Download';
            downloadBtn.className = 'action-btn download-btn';
            downloadBtn.addEventListener('click', () => {
                window.location.href = `/download/${file.id}`;
            });

            // Delete button
            const deleteBtn = document.createElement('button');
            deleteBtn.textContent = 'Delete';
            deleteBtn.className = 'action-btn delete-btn';
            deleteBtn.addEventListener('click', async () => {
                if (confirm('Are you sure you want to delete this file?')) {
                    const csrfToken = getCSRFToken();
                    const response = await fetch(`/delete/${file.id}`, {
                        method: 'POST',
                        headers: {
                            'X-CSRFToken': csrfToken
                        }
                    });
                    const result = await response.json();
                    if (response.ok) {
                        alert(result.message);
                        fetchFiles();  // Refresh the file list
                    } else {
                        alert(`Error: ${result.message}`);
                    }
                }
            });

            actionsCell.appendChild(downloadBtn);
            actionsCell.appendChild(deleteBtn);

            row.appendChild(filenameCell);
            row.appendChild(uploadTimeCell);
            row.appendChild(actionsCell);

            filesTableBody.appendChild(row);
        });
    }
}
