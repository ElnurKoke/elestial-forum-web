# ELESTIAL 

Now each user has his own personal profile

## King
- **delete or add category**
- **promote or demote any user,moderator,admin**
- **delete any comment or post**
## Admin
- **respond to moderators**
- **promote or demote user and moderator**
- **delete any comment or post**
## Moderator
- **accept posts**
- **send reports to admin**
- **promote user**


Security is an important part of web forum development. First of all, we create a self-signed certificate for ourselves. The openssl utility will help with this. We created a private key for ourselves generated using the RSA cryptoalgorithm. Now the connection to the browser is via the TLS protocol, and there we will indicate which certificates to use.
We will set a time limit for the request and response to avoid DOS attacks.

In forum image upload, registered users have the possibility to create a post containing an image as well as text.

When you sign up for the forum, your username, email address, and password are checked to make sure they follow certain rules. Your username must be between 6 and 36 characters long and contain only letters and numbers. Your email address must be correct, and your password must be between 8 and 20 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character, like ! or @. If anything doesn't meet these rules, you'll get an error message and can fix your input before continuing with the registration.

When registering on the forum, you can also choose to sign up using your Google or GitHub account. This means you don't have to create a separate username and password for the forum if you already have an account with Google or GitHub. Just click on the respective button for Google or GitHub registration, and you'll be redirected to their login page. After signing in with your Google or GitHub credentials, you'll be automatically registered and logged in to the forum. This simplifies the registration process and provides an alternative way to access the forum without creating a new account from scratch.

When viewing the post, users and guests should see the image associated to it.
There are several extensions for images like: JPEG, SVG, PNG, GIF, etc. In this project you have to handle at least JPEG, PNG and GIF types.

The max size of the images to load should be 20 mb. If there is an attempt to load an image greater than 20mb, an error message should inform the user that the image is too big.

## Overview
This project is a forum application designed to facilitate communication and interaction between users. It includes features such as authentication with tokens, communication between users, categorizing posts, liking and disliking posts and comments, as well as filtering posts. Users can also edit and delete their own posts and comments.

## Features
- **Authentication with Tokens**: Users can authenticate themselves using tokens for secure access to the forum.
- **Communication Between Users**: Users can interact with each other through posts and comments.
- **Associating Categories to Posts**: Posts can be categorized to organize discussions effectively.
- **Liking and Disliking Posts and Comments**: Users can express their opinions on posts and comments by liking or disliking them.
- **Filtering Posts**: Users can filter posts based on categories or other criteria to find relevant content.
- **Editing and Deleting Posts and Comments**: Users have the ability to edit and delete their own posts and comments.

## Technologies Used
- **Backend**: Golang
- **Database**: SQLite, Redis
- **Authentication**: [UUID](https://github.com/gofrs/uuid), [bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt)
- **Frontend**: HTML, CSS, JavaScript

## Installation
1. Clone the repository: `git clone <repository_url>`
2. Navigate to the project directory: `cd forum-project`
3. Run Locally with makefile: ```make run```
4. And go to the web page: `https://localhost:8080`
5. Run docker: 
```
docker build -t forum .
docker run -it -p 8080:8080 forum
make dStop
make dDelete
make dDeleteImages
```

## Usage
1. Register a new account or login with existing credentials.
2. Explore categories or create new posts within categories.
3. Interact with other users by commenting on their posts or liking/disliking their content.
4. Utilize the filtering options to find specific posts or categories.
5. Manage your own posts and comments by editing or deleting them as needed.


## Contact
For any inquiries or support regarding this project, feel free to contact [Elnur Bauyrzhan tgm: @EL_n_UR 
Discord: https://discordapp.com/users/762269394034229248/ 
gitea: https://01.alem.school/git/ebauyrzh].
