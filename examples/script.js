// websocket for receiving messages
let ws = null;

// list of registered identities
const registered = [];

// load identities from local storage and render them to the dom
const updateIdentities = async () => {
  const identities = Object.keys(window.localStorage).reduce(
    (acc, item) => {
      if (item.startsWith('did:')) {
        const identity = JSON.parse(window.localStorage.getItem(item));

        return { [identity.id]: identity, ...acc };
      }

      return acc;
    }, {});

  const cards = document.querySelector('.cards');

  // clear cards if no identities
  if (Object.values(identities).length === 0) {
    cards.innerHTML = `
    <div class="text-muted p-3">
      <em>None</em>
    </div>`;
  } else {
    cards.innerHTML = '';
  }

  Object.values(identities).forEach((identity) => {
    const card = document.createElement('div');
    card.classList.add('col');

    card.innerHTML = `
    <div class="card mb-4 text-bg-light" style="max-width:40rem">
      <div class="card-body">
        ${identity.sigkey ? '' : '<span class="badge bg-success float-end">verified</span>'}
        <h5 class="card-title">
          ${identity.sigkey ? 'Private' : 'Public'} VID
        </h5>
        <input type="text" value="${identity.id}" class="form-control-plaintext" readonly />
      </div>
      <ul class="list-group list-group-flush">
        ${identity.sigkey ? `
          <li class="list-group-item">
              <span class="badge text-bg-warning float-end">private</span>
              <span class="text-muted d-block mb-2">Decryption key:</span>
              <pre class="text-warning-emphasis mb-0">${identity.enckey}</pre>
          </li>
          <li class="list-group-item">
              <span class="badge text-bg-warning float-end">private</span>
              <span class="text-muted d-block mb-2">Signing key:</span>
              <pre class="text-warning-emphasis mb-0">${identity.sigkey}</pre>
          </li>
        ` : ''}
        <li class="list-group-item">
            <span class="badge text-bg-info float-end">public</span>
            <span class="text-muted d-block mb-2">Verification key:</span>
            <pre class="text-primary-emphasis mb-0">${identity.publicSigkey}</pre>
        </li>
        <li class="list-group-item">
            <span class="badge text-bg-info float-end">public</span>
            <span class="text-muted d-block mb-2">Encryption key:</span>
            <pre class="text-primary-emphasis mb-0">${identity.publicEnckey}</pre>
        </li>
        <li class="list-group-item">
          <span class="text-muted d-block mb-2">Transport:</span>
          <pre class="text-primary-emphasis mb-0">${identity.transport}</pre>
        </li>
      </ul>
      <div class="card-body">
        <button role="button" class="btn btn-danger delete float-end">Delete</button>
        ${identity.sigkey ? `<button role="button" class="btn btn-warning select-sender">Select sender</button>` : ''}
        <button role="button" class="btn btn-info select-receiver">Select receiver</button>
      </div>
    </div>`;

    // add event listeners
    card
      .querySelector('.delete')
      .addEventListener('click', (event) => {
        event.preventDefault();
        window.localStorage.removeItem(identity.id);
        updateIdentities();
      });

    card
      .querySelector('.select-receiver')
      .addEventListener('click', (event) => {
        event.preventDefault();
        document.getElementById('receiver').value = identity.id;
      });

    const selectSender = card.querySelector('.select-sender');
    if (selectSender) {
      selectSender.addEventListener('click', (event) => {
        event.preventDefault();
        document.getElementById('sender').value = identity.id;
      });
    }

    cards.appendChild(card);
  });

  // listen for messages on websocket
  if (!ws) {
    function connectWS() {
      const proto = window.location.protocol === 'http:' ? 'ws' : 'wss';
      ws = new WebSocket(`${proto}://${window.location.host}/receive-messages`);
      ws.addEventListener('message', (event) => {
        const message = JSON.parse(event.data);
        const messagesContainer = document.querySelector('.received-messages');
        messagesContainer.appendChild(renderMessage(message));
      });
      ws.addEventListener('open', () => {
        Object.values(identities).forEach((identity) => {
          ws.send(JSON.stringify(identity));
          registered.push(identity.id);
        });
      });
      ws.addEventListener('close', connectWS);
    }
    connectWS();
  }
};

/**
 * Add a span to an element with text contents
 * @param {HTMLElement} parent
 * @param {string} text
 * @param {string?} classes optional space-separated CSS classes to apply
 * @param {{string: string}?} style optional CSS styles to apply
 * @return {HTMLSpanElement}
 */
function addSpan(parent, text, classes, style) {
  const span = document.createElement('span');
  span.textContent = text;
  if (classes) span.classList.add(...classes.split(' '));
  if (style) Object.assign(span.style, style);
  parent.appendChild(span);
}

// render a TSP message with debug information
function renderMessage(message) {
  const card = document.createElement('div');
  card.classList.add('col');

  const parts = ['prefix', 'sender', 'receiver', 'nonconfidentialData', 'ciphertext', 'signature'];
  const colors = ['#800000', '#911eb4', '#000075', '#3cb44b', '#9A6324', '#469990'];

  card.innerHTML = `
  <div class="card mb-4 text-bg-light" style="max-width:40rem">
    <div class="card-body">
      <span class="float-end">${(new Date()).toISOString().slice(0, 19).replace('T', ' ')}</span>
      <h5 class="card-title">Message</h5>
      <p class="card-text"></p>
    </div>
    <ul class="list-group list-group-flush"></ul>
  </div>`;

  const messageParts = card.querySelector('p.card-text');
  parts.forEach((part, index) => {
    if (message[part]) {
      addSpan(messageParts, message[part].data, 'message-part', { 'color': colors[index] });
    }
  });

  const partsList = card.querySelector('ul');
  parts.forEach((part, index) => {
    if (!message[part]) return;

    const li = document.createElement('li');
    li.classList.add('list-group-item');

    if (part === 'sender' || part === 'signature') {
      if (message.ciphertext.plain) {
        addSpan(li, 'Verified', 'badge bg-success float-end');
      } else {
        addSpan(li, 'Unverified', 'badge bg-danger float-end');
      }
      addSpan(li, part === 'sender' ? message.cryptoType : message.signatureType, 'badge text-bg-secondary float-end', { 'margin-right': '0.375rem' });
    }

    addSpan(li, message[part].title, 'text-muted d-block');

    if (message[part].plain) {
      addSpan(li, message[part].plain, 'd-block');
    }

    addSpan(li, `CESR selector: ${message[part].prefix}`, 'message-part d-block');
    addSpan(li, message[part].data, 'message-part d-block', { 'color': colors[index] });

    if (part === 'sender' && !message.ciphertext.plain) {
      const button = document.createElement('button');
      button.classList.add('btn', 'btn-outline-primary', 'mt-2', 'verify');
      button.textContent = 'Verify sender';
      li.appendChild(button);
    }

    partsList.appendChild(li);
  });

  const verifySender = card.querySelector('.verify');
  if (verifySender) {
    verifySender.addEventListener('click', (event) => {
      event.preventDefault();
      const formData = new FormData();
      formData.append('vid', message.sender.plain);

      if (resolveVid(formData)) {
        if (card.parentNode) {
          card.parentNode.removeChild(card);
        }

        setTimeout(() => {
          ws.send(JSON.stringify({
            sender: message.sender.plain,
            receiver: message.receiver.plain,
            message: message.original,
          }));
        }, 500);
      }
    });
  }

  return card;
}

// create vid form
const createForm = document.getElementById('create-identity');

createForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new URLSearchParams(new FormData(createForm));
  const response = await fetch('/create-identity', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
    },
    body: formData,
  });

  if (response.ok) {
    createForm.reset();
    const identity = await response.json();
    const key = identity.id;
    window.localStorage.setItem(key, JSON.stringify(identity));
    updateIdentities();
    ws.send(JSON.stringify(identity));
  } else {
    window.alert('Failed to create identity, this VID might already exist');
  }
});

// resolve vid form
async function resolveVid(formData) {
  const body = new URLSearchParams(formData);
  const response = await fetch('/verify-vid', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
    },
    body: body,
  });

  if (response.ok) {
    resolveForm.reset();
    const identity = await response.json();
    const key = identity.id;
    window.localStorage.setItem(key, JSON.stringify(identity));
    updateIdentities();
    ws.send(JSON.stringify(identity));

    return true;
  }

  window.alert('Failed to resolve and verify VID');

  return false;
}

const resolveForm = document.getElementById('resolve-vid');

resolveForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  resolveVid(new FormData(resolveForm));
});

// send TSP message form
const sendMessageForm = document.getElementById('send-message');

sendMessageForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  if (!sendMessageForm.sender.value || !sendMessageForm.receiver.value) {
    return window.alert('Please select sender and receiver');
  }

  if (!window.localStorage.getItem(sendMessageForm.sender.value)) {
    return window.alert('Sender identity not found');
  }

  if (!window.localStorage.getItem(sendMessageForm.receiver.value)) {
    return window.alert('Receiver identity not found');
  }

  const formData = {
    sender: JSON.parse(
      window.localStorage.getItem(sendMessageForm.sender.value)
    ),
    receiver: JSON.parse(
      window.localStorage.getItem(sendMessageForm.receiver.value)
    ),
    nonconfidential_data: sendMessageForm.nonconfidential.value,
    message: sendMessageForm.message.value,
  };
  const response = await fetch('/send-message', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json;charset=UTF-8',
    },
    body: JSON.stringify(formData),
  });

  if (response.ok) {
    sendMessageForm.nonconfidential.value = '';
    sendMessageForm.message.value = '';
    const message = await response.json();

    const messagesContainer = document.querySelector('.messages');
    messagesContainer.innerHTML = '';
    messagesContainer.appendChild(renderMessage(message));
  } else {
    window.alert('Failed to create the TSP message');
  }
});

// initial load
updateIdentities();
