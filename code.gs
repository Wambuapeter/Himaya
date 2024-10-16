function Himaya() {
  // Get the first few emails from your inbox (10 in this case)
  var threads = GmailApp.getInboxThreads(0, 10);
  
  // A regular expression to match URLs (http, https, ftp, file, or domain links)
  var urlRegex = /(\b(https?|ftp|file):\/\/[^\s]+|\bwww\.[^\s]+|\b[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+[^\s]*)/g;

  // Loop through each email thread and get its messages
  for (var i = 0; i < threads.length; i++) {
    var messages = threads[i].getMessages();
    
    for (var j = 0; j < messages.length; j++) {
      var email = messages[j];
      
      // Log the subject and body of each email for testing
      Logger.log('Subject: ' + email.getSubject());
      Logger.log('Body: ' + email.getPlainBody());

      // Extract links from the email body
      var body = email.getPlainBody();
      var links = body.match(urlRegex);
      
      if (links) {
        Logger.log('Links found: ' + links.join(', '));
      } else {
        Logger.log('No links found in this email.');
      }

      // Extract attachments from the email
      var attachments = email.getAttachments();
      
      if (attachments.length > 0) {
        for (var k = 0; k < attachments.length; k++) {
          var attachment = attachments[k];
          Logger.log('Attachment Name: ' + attachment.getName());
          Logger.log('Attachment Size: ' + attachment.getSize() + ' bytes');
        }
      } else {
        Logger.log('No attachments found in this email.');
      }
    }
  }
}

