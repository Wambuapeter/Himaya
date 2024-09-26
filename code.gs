function getEmails() {
  // Get the first few inboxes from your email(10 in this case)
  var threads = GmailApp.getInboxThreads(0, 10);
  
  // Loop through each inbox and get its messages
  for (var i = 0; i < threads.length; i++) {
    var messages = threads[i].getMessages();
    
    for (var j = 0; j < messages.length; j++) {
      var email = messages[j];
      
      // Log the subject and body of each email -> for testing
      Logger.log('Subject: ' + email.getSubject());
      Logger.log('Body: ' + email.getPlainBody());
    }
  }
}


function onOpen(e) {
  var card = createCard();
  return card.build();
}

function createCard() {
  var card = CardService.newCardBuilder();
  var cardHeader = CardService.newCardHeader()
    .setTitle('Check Links')
    .setSubtitle('Detect links in the email');

  var cardSection = CardService.newCardSection()
    .addWidget(CardService.newTextButton()
      .setText('Detect Links')
      .setOnClickAction(CardService.newAction()
        .setFunctionName('detectLinksAction')));

  return card.setHeader(cardHeader).addSection(cardSection);
}

function detectLinksAction(e) {
  var messageId = e.gmail.messageId;
  var message = GmailApp.getMessageById(messageId);
  var body = message.getPlainBody();
  var links = extractUrls(body);
  
  var result = "<b>Links found in the email:</b><br><br>";

  if (links.length > 0) {
    for (var i = 0; i < links.length; i++) {
      var link = links[i];
      var isMalicious = checkMalicious(link);
      if (isMalicious === true) {
        result += '<font color="red">' + link + ": Malicious</font><br>";
      } else if (isMalicious === false) {
        result += '<b color="#ff00ff">' + link + ": Safe</b><br>";
      } else {
        result += link + ": Unknown status<br>";
      }
    }
  } else {
    result += "No links found in the email.";
  }

  var card = CardService.newCardBuilder();
  var cardHeader = CardService.newCardHeader()
    .setTitle('Check Links Result');
  
  var cardSection = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(result))
    .setHeader(cardHeader);

  return card.addSection(cardSection).build();
}

function extractUrls(text){
  var regex = /(https?:\/\/[^\s]+)/g;
  var urls = [];
  var match;
  
  while ((match = regex.exec(text)) !== null) {
    urls.push(match[0]);
  }
  
  return urls;
}

function checkMalicious(link) {
  var apiKey = '0803f148c57720140be7017a5db6fdde0b7fccf6c9e7174410f40eacbb6239e1';
  var scanUrl = 'https://www.virustotal.com/vtapi/v2/url/report';
  var params = {
    'method': 'post',
    'contentType': 'application/x-www-form-urlencoded',
    'muteHttpExceptions': true,
    'payload': {
      'apikey': apiKey,
      'resource': link
    }
  };
  var response = UrlFetchApp.fetch(scanUrl, params);
  
  if (response.getResponseCode() == 200) {
    var json = response.getContentText();
    var data = JSON.parse(json);
    
    if (data.response_code === 1 && data.positives > 0) {
      return true; // Malicious
    } else if (data.response_code === 1) {
      return false; // Safe
    } else {
      return null; // Unknown status
    }
  } else {
    Logger.log('Error fetching URL: ' + scanUrl + ', Response code: ' + response.getResponseCode());
    return null;
  }
}
