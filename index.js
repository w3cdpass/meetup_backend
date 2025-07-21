require("dotenv").config();
const express = require('express');
const { User, Chat } = require('./models/User');
const { createServer } = require('node:http');
const { Server } = require('socket.io');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
const app = express();
const client = new OAuth2Client();
const cookieParser = require('cookie-parser');
const cookie = require('cookie');
const jwt = require('jsonwebtoken');
const { default: mongoose } = require("mongoose");
const authMiddleware = require("./middlewares/authMiddleware");
const { Socket } = require("node:dgram");


app.use(cors({
  // origin: process.env.NODE_ENV === 'development'
  //     ? 'http://localhost:5173' // Vite dev server
  //     : 'app://./' ,// Electron production

  // curl -i -X OPTIONS http://localhost:3000/ -H "Origin: http://localhost:5173
  origin: ['https://meetcode-phi.vercel.app'],
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true
}));

// JWT_SECRET
const Jwt_Token = process.env.JWT_SECRET
// mongoose connection 
const DB = process.env.MONGO_URI 
// connection to the mongoose
mongoose.connect(DB, { useNewUrlParser: true, useUnifiedTopology: true }).then(() =>
  console.log('Data base connected'));
app.use(express.json());
app.use(cookieParser());

/**
 * GET /
 *
 * Root endpoint that requires authentication.
 * Returns a simple JSON response if the user is authenticated.
 *
 * @route GET /
 * @middleware authMiddleware
 * @param {import('express').Request} req - Express request object (user info attached by authMiddleware).
 * @param {import('express').Response} res - Express response object.
 * @returns {void} 200 with JSON if authenticated, 500 on error.
 */
app.get('/', authMiddleware, (req, res) => {
  try {
    res.json({ '/': 'Authenticated User' })
  } catch (error) {
    res.status(500).json({ message: 'Error fetching user', error: error.message });

  }
})


/**
 * GET /api/me
 *
 * Returns the authenticated user's profile and friend requests.
 * Requires authentication via authMiddleware.
 *
 * @route GET /api/me
 * @middleware authMiddleware
 * @param {import('express').Request} req - Express request object (user info attached by authMiddleware).
 * @param {import('express').Response} res - Express response object.
 * @returns {void} 200 with user JSON, 404 if not found, 500 on error.
 */
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate(
      'friendRequestsReceived',
      'name picture _id',
    );
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ message: 'Error fetching user', error: err.message });
  }
});



/**
 * POST /
 *
 * Authenticates a user using a Google ID token from the frontend (OAuth login).
 *
 * Flow:
 *   1. Expects a Google ID token in the request body: { token: string }
 *   2. Verifies the token with Google using google-auth-library.
 *   3. Extracts user info from the token payload (sub, email, name, picture).
 *   4. Checks if a user with the given Google ID (sub) exists in the database:
 *      - If found, uses the existing user.
 *      - If not found, creates a new user with the info from Google.
 *   5. Generates a JWT token containing the user's MongoDB _id and email.
 *   6. Sets the JWT as an HTTP-only cookie in the response for session management.
 *   7. Returns a JSON response with a success message and the user object.
 *
 * Error handling:
 *   - If the token is missing, responds with 400 and an error message.
 *   - If the token is invalid or verification fails, responds with 401 and an error message.
 *
 * Example request body:
 *   {
 *     "token": "<Google ID token>"
 *   }
 *
 * Example success response (200):
 *   {
 *     "message": "Login success",
 *     "user": { ...user fields }
 *   }
 *
 * Example error responses:
 *   400: { "error": "Missing token" }
 *   401: { "error": "Invalid token" }
 *
 * @route POST /
 * @param {import('express').Request} req - Express request object (expects { token } in body).
 * @param {import('express').Response} res - Express response object.
 * @returns {void} Sets JWT cookie and returns user on success, error JSON on failure.
 */
app.post('/', async (req, res) => {
  const token = req.body.token;
  if (!token) {
    return res.status(400).json({ error: 'Missing token' });
  }
  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      // audience: keys.web.client_id,
    });

    const payload = ticket.getPayload();
    // console.log("✅ Token verified:", payload);
    let user = await User.findOne({ googleId: payload.sub });
    if (!user) {
      user = await User.create({
        googleId: payload.sub,
        email: payload.email,
        name: payload.name,
        picture: payload.picture,
      });
    }
    const appToken = jwt.sign({
      userId: user._id.toString(),
      email: user.email,
    }, Jwt_Token, { expiresIn: '30hr' });
    res.cookie("token", appToken, {
      httpOnly: true,
      sameSite: "None",
      secure: true,
    })
    res.status(200).json({ message: 'Login success', user });
  } catch (error) {
    console.error('Token verification failed:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
})


/**
 * GET /frnd-req/:senderId
 *
 * Sends a friend request from the authenticated user (receiver) to another user (senderId).
 *
 * Flow:
 *   1. Extracts the authenticated user's ID from the JWT (receiverId) and the senderId from the URL.
 *   2. Validates that senderId is a valid MongoDB ObjectId and not the same as receiverId (no self-requests).
 *   3. Fetches both sender and receiver from the database. Returns 404 if either is missing.
 *   4. Checks if a friend request has already been sent or if they are already friends. If so, redirects to /chats.
 *   5. If not, adds senderId to receiver's friendRequestsReceived and receiverId to sender's friendRequestsSent.
 *   6. Saves both user documents and redirects to /chats.
 *
 * Error responses:
 *   400: Invalid sender ID or self-request
 *   404: User not found
 *
 * Success:
 *   Redirects to /chats (http://localhost:5173/chats) after sending or if already sent/friends.
 *
 * @route GET /frnd-req/:senderId
 * @middleware authMiddleware
 * @param {import('express').Request} req - Express request object (user info attached by authMiddleware).
 * @param {import('express').Response} res - Express response object.
 * @returns {void} Redirects to /chats on success or duplicate, 400/404 on error.
 */
app.get('/frnd-req/:senderId', authMiddleware, async (req, res) => {
  const receiverId = req.user.userId;         // Authenticated user (e.g. Rahul)
  const senderId = req.params.senderId;       // ID in the URL (e.g. Vikas)

  if (!mongoose.isValidObjectId(senderId)) {
    return res.status(400).json({ error: 'Invalid sender ID' });
  }

  if (receiverId === senderId) {
    return res.status(400).json({ error: "You can't send a request to yourself." });
  }

  const sender = await User.findById(senderId);
  const receiver = await User.findById(receiverId);

  if (!sender || !receiver) {
    return res.status(404).json({ error: 'User not found' });
  }

  // Check if already friends or already sent
  if (
    receiver.friendRequestsReceived.includes(senderId) ||
    receiver.friends.includes(senderId)
  ) {
    return res.redirect('http://localhost:5173/chats');
  }

  // Add friend request
  receiver.friendRequestsReceived.push(senderId);
  sender.friendRequestsSent.push(receiverId);

  await receiver.save();
  await sender.save();

  return res.redirect('http://localhost:5173/chats');
});




/**
 * POST /frnd-req/:senderId/accept
 *
 * Accepts a friend request for the authenticated user (receiver) from another user (senderId).
 *
 * Flow:
 *   1. Extracts the receiver's userId from the JWT and senderId from the URL.
 *   2. Fetches both sender and receiver from the database. Returns 404 if either is missing.
 *   3. Checks if the sender actually sent a friend request to the receiver. If not, returns 400.
 *   4. Adds each user to the other's friends list.
 *   5. Removes the friend request from both users' request arrays.
 *   6. Finds or creates a chat between the two users.
 *   7. Adds the chat to both users' chat lists if not already present.
 *   8. Saves all changes and returns a success response with the chat ID.
 *
 * Error handling:
 *   - 404: If either user is not found.
 *   - 400: If there is no friend request from the sender.
 *   - 500: On server/database errors.
 *
 * Example success response (200):
 *   {
 *     "message": "Friend request accepted.",
 *     "chatId": "<chat id>"
 *   }
 *
 * Example error responses:
 *   404: { "message": "User not found." }
 *   400: { "message": "No friend request from this user." }
 *   500: { "message": "Server error." }
 *
 * @route POST /frnd-req/:senderId/accept
 * @middleware authMiddleware
 * @param {import('express').Request} req - Express request object (user info attached by authMiddleware).
 * @param {import('express').Response} res - Express response object.
 * @returns {void} 200 with chatId on success, error JSON on failure.
 */
app.post('/frnd-req/:senderId/accept', authMiddleware, async (req, res) => {
  try {
    const receiverId = req.user.userId; // the logged-in user
    const senderId = req.params.senderId;

    const sender = await User.findById(senderId);
    const receiver = await User.findById(receiverId);

    if (!sender || !receiver) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check if sender actually sent a request
    if (!receiver.friendRequestsReceived.includes(senderId)) {
      return res.status(400).json({ message: "No friend request from this user." });
    }

    // Add each other as friends
    sender.friends.push(receiverId);
    receiver.friends.push(senderId);

    // Remove request from both sides
    sender.friendRequestsSent = sender.friendRequestsSent.filter(id => id.toString() !== receiverId);
    receiver.friendRequestsReceived = receiver.friendRequestsReceived.filter(id => id.toString() !== senderId);

    let chat = await Chat.findOne({
      participants: { $all: [senderId, receiverId], $size: 2 }
    });

    if (!chat) {
      chat = await Chat.create({
        participants: [senderId, receiverId],
        messages: []
      })
    }

    if (!sender.chats.includes(chat._id)) sender.chats.push(chat._id);
    if (!receiver.chats.includes(chat._id)) receiver.chats.push(chat._id);

    await chat.save()
    await sender.save();
    await receiver.save();

    return res.status(200).json({ message: "Friend request accepted.", chatId: chat._id });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
});


/**
 * POST /frnd-req/:senderId/decline
 *
 * Declines a friend request for the authenticated user (receiver) from another user (senderId).
 *
 * Flow:
 *   1. Extracts the receiver's userId from the JWT and senderId from the URL.
 *   2. Fetches both sender and receiver from the database. Returns 404 if either is missing.
 *   3. Checks if the sender actually sent a friend request to the receiver. If not, returns 400.
 *   4. Removes the friend request from both users' request arrays (sent and received).
 *   5. Saves both user documents.
 *   6. Returns a success response indicating the request was declined.
 *
 * Error handling:
 *   - 404: If either user is not found.
 *   - 400: If there is no friend request from the sender.
 *   - 500: On server/database errors.
 *
 * Example success response (200):
 *   {
 *     "message": "Friend request declined."
 *   }
 *
 * Example error responses:
 *   404: { "message": "User not found." }
 *   400: { "message": "No friend request from this user." }
 *   500: { "message": "Server error." }
 *
 * @route POST /frnd-req/:senderId/decline
 * @middleware authMiddleware
 * @param {import('express').Request} req - Express request object (user info attached by authMiddleware).
 * @param {import('express').Response} res - Express response object.
 * @returns {void} 200 on success, error JSON on failure.
 */
app.post('/frnd-req/:senderId/decline', authMiddleware, async (req, res) => {
  try {
    const receiverId = req.user.userId;
    const senderId = req.params.senderId;

    const sender = await User.findById(senderId);
    const receiver = await User.findById(receiverId);

    if (!sender || !receiver) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check if sender sent a request
    if (!receiver.friendRequestsReceived.includes(senderId)) {
      return res.status(400).json({ message: "No friend request from this user." });
    }

    // Remove request from both users
    sender.friendRequestsSent = sender.friendRequestsSent.filter(id => id.toString() !== receiverId);
    receiver.friendRequestsReceived = receiver.friendRequestsReceived.filter(id => id.toString() !== senderId);

    await sender.save();
    await receiver.save();

    return res.status(200).json({ message: "Friend request declined." });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
});



/**
 * GET /chats
 *
 * Returns a list of the authenticated user's friends, each with chat information and last message activity.
 *
 * Flow:
 *   1. Extracts the authenticated user's userId from the JWT.
 *   2. Fetches the user from the database and populates their friends list.
 *   3. For each friend, also populates the chat(s) between the user and that friend, selecting chat ID and last message time.
 *   4. Maps each friend to an object containing their info, the chatId, and lastMessageAt.
 *   5. Sorts the friends by most recent chat activity (descending).
 *   6. Returns the sorted list as JSON.
 *
 * Error handling:
 *   - 500: On server/database errors, returns an error message.
 *
 * Example success response (200):
 *   {
 *     "friends": [
 *       {
 *         "_id": "...",
 *         "name": "...",
 *         "email": "...",
 *         "picture": "...",
 *         "socketId": "...",
 *         "chatId": "...",
 *         "lastMessageAt": "..."
 *       },
 *       ...
 *     ]
 *   }
 *
 * Example error response:
 *   500: { "error": "Failed to load friends" }
 *
 * @route GET /chats
 * @middleware authMiddleware
 * @param {import('express').Request} req - Express request object (user info attached by authMiddleware).
 * @param {import('express').Response} res - Express response object.
 * @returns {void} 200 with friends and chat info on success, error JSON on failure.
 */
app.get('/chats', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const user = await User.findById(userId)
      .populate({
        path: 'friends',
        select: 'name email picture socketId',
        populate: {
          path: 'chats',
          select: '_id participants lastMessageAt',
          match: { participants: userId }
        }
      })
      .exec();

    // Enhance friends data with chat info
    const friendsWithChats = user.friends.map(friend => {
      const chat = friend.chats?.[0]; // Get the chat between current user and this friend
      return {
        ...friend.toObject(),
        chatId: chat?._id,
        lastMessageAt: chat?.lastMessageAt
      };
    });

    // Sort friends by most recent chat activity
    friendsWithChats.sort((a, b) => {
      const dateA = a.lastMessageAt || new Date(0);
      const dateB = b.lastMessageAt || new Date(0);
      return dateB - dateA;
    });

    res.json({ friends: friendsWithChats });
  } catch (error) {
    console.error('Error fetching friends:', error);
    res.status(500).json({ error: 'Failed to load friends' });
  }
});

// Get or create a chat between current user and another user
// GET /chat/:chatId/messages
/**
 * GET /chats/:chatId/messages
 *
 * Returns the messages for a specific chat if the authenticated user is a participant.
 *
 * Flow:
 *   1. Extracts chatId from the URL and userId from the JWT.
 *   2. Fetches the chat by ID and populates the participants' names and messages.
 *   3. Checks if the authenticated user is a participant in the chat. If not, returns 403.
 *   4. Returns the chat object (including messages) as JSON.
 *
 * Error handling:
 *   - 403: If the user is not a participant in the chat.
 *   - 500: On server/database errors, returns an error message.
 *
 * Example success response (200):
 *   {
 *     "messages": { ...chat object with messages and participants... }
 *   }
 *
 * Example error responses:
 *   403: { "error": "Access denied" }
 *   500: { "error": "Failed to fetch messages" }
 *
 * @route GET /chats/:chatId/messages
 * @middleware authMiddleware
 * @param {import('express').Request} req - Express request object (user info attached by authMiddleware).
 * @param {import('express').Response} res - Express response object.
 * @returns {void} 200 with chat messages on success, error JSON on failure.
 */
app.get('/chats/:chatId/messages', authMiddleware, async (req, res) => {
  try {
    const { chatId } = req.params;
    const userId = req.user.userId;
    const chat = await Chat.findById(chatId).populate('participants', 'name messages')
    const chats = chat.participants
    if (!chats.find((value) => value._id.toString() === userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }


    const messages = chat || [];
    // const messages = (chat?.messages || []).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    res.json({ messages });
  } catch (error) {
    console.error('Error fetching chat messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});



const server = createServer(app);
// const io = new Server(server, {
//   cors: {
//     origin: ['http://localhost:5173', 'http://localhost:3000'],
//     methods: ["GET", "POST"],
//     credentials: true
//   }
// });

const io = new Server(server, {
  cors: {
    origin: ['https://meetcode-phi.vercel.app'],
    methods: ["GET", "POST"],
    credentials: true
  }
});




/**
 * Socket.IO connection handler
 *
 * Handles real-time events for authenticated users, including joining rooms, typing notifications,
 * sending messages, and disconnects. Authenticates users via JWT in cookies and manages user sessions.
 *
 * Flow:
 *   1. On connection, parses cookies to extract the JWT token.
 *   2. Verifies the JWT and fetches the user from the database.
 *   3. If authentication fails or user not found, disconnects the socket.
 *   4. Saves the user's socket ID in the onlineUsers map.
 *   5. Joins a room for each friend (room name is a sorted combination of user IDs).
 *   6. Listens for and emits the following events:
 *
 * Socket Events:
 *
 * - join_debug
 *   - .on('join_debug', () => ...)
 *   - Logs the rooms the socket is currently in. Used for debugging room membership.
 *   - See: https://socket.io/docs/v4/rooms/
 *
 * - typing
 *   - .on('typing', ({ chatId, senderId }) => ...)
 *   - Broadcasts a 'user typing' event to all other sockets, indicating a user is typing in a chat.
 *   - Emits: 'user typing' with { chatId, senderId }
 *   - See: https://socket.io/docs/v4/emitting-events/
 *
 * - stop typing
 *   - .on('stop typing', ({ chatId, senderId }) => ...)
 *   - Broadcasts a 'user stop typing' event to all other sockets, indicating a user stopped typing.
 *   - Emits: 'user stop typing' with { chatId, senderId }
 *
 * - send_message
 *   - .on('send_message', ({ to, text }) => ...)
 *   - Validates that the recipient is a friend.
 *   - Emits: 'receive_message' to the chat room with the message object { from, to, text, timestamp }
 *   - If recipient is not a friend, emits: 'error' with { message: "User is not your friend" }
 *   - Saves the message to the database after a delay.
 *   - See: https://socket.io/docs/v4/emitting-events/
 *
 * - disconnect
 *   - .on('disconnect', () => ...)
 *   - Logs disconnection and cleans up the onlineUsers map.
 *   - See: https://socket.io/docs/v4/server-api/#event-disconnect
 *
 * Example message event sent from client:
 *   socket.emit('send_message', { to: '<friend userId>', text: 'Hello!' })
 *
 * Example message event received by client:
 *   socket.on('receive_message', (message) => { ... })
 *
 * Example room name:
 *   createRoomName('userId1', 'userId2') // returns 'userId1_userId2' (sorted)
 *
 * Error handling:
 *   - If JWT is missing or invalid, disconnects the socket.
 *   - If the recipient is not a friend, emits an error event.
 *
 * For more on Socket.IO events and rooms, see:
 *   - https://socket.io/docs/v4/rooms/
 *   - https://socket.io/docs/v4/emitting-events/
 *   - https://socket.io/docs/v4/server-api/
 *
 * @event connection
 * @param {import('socket.io').Socket} ConnectionSocket - The connected socket instance.
 */
const onlineUsers = new Map();
const typingUsers = new Set();
io.on('connection', async (ConnectionSocket) => {
  const cookies = cookie.parse(ConnectionSocket.handshake.headers.cookie || '')
  // console.log(cookies.token)
  const token = cookies.token;

  if (!token) return ConnectionSocket.disconnect(true)
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;
    // console.log(userId)
    const user = await User.findById(userId).populate('friends');
    if (!user) return ConnectionSocket.disconnect(true)

    // Save user ID
    onlineUsers.set(ConnectionSocket.id, userId);

    console.log(`✅ User ${user.name} connected (${ConnectionSocket.id})`);

    user.friends.forEach((friend) => {
      const friendId = friend._id?.toString?.() || friend.toString();
      const roomName = createRoomName(userId, friendId);
      ConnectionSocket.join(roomName);
    });


    /**
     * join_debug event
     *
     * Logs the rooms the current socket is in. Used for debugging room membership.
     *
     * @event join_debug
     * @memberof SocketIOConnection
     * @example
     * socket.emit('join_debug');
     * // Server logs: Socket <id> is in rooms: [...]
     * @augments _id if it is not returning the only `_id` in object but a whole user Infomation in object 
     * @see https://socket.io/docs/v4/rooms/
     */
    ConnectionSocket.on("join_debug", () => {
      const rooms = [...ConnectionSocket.rooms];
      console.log(`Socket ${ConnectionSocket.id} is in rooms:`, rooms);
    });

    /**
     * typing event
     *
     * Broadcasts a 'user typing' event to all other sockets, indicating a user is typing in a chat.
     *
     * @event typing
     * @memberof SocketIOConnection
     * @param {Object} data - The typing event payload.
     * @param {string} data.chatId - The chat room ID.
     * @param {string} data.senderId - The user ID of the sender.
     * @example
     * socket.emit('typing', { chatId: '...', senderId: '...' });
     * // Other clients receive: socket.on('user typing', ...)
     */
    ConnectionSocket.on('typing', ({ chatId, senderId }) => {
      typingUsers.add(`${chatId}: ${senderId}`);
      ConnectionSocket.broadcast.emit('user typing', {
        chatId, senderId
      })
    })

    /**
     * stop typing event
     *
     * Broadcasts a 'user stop typing' event to all other sockets, indicating a user stopped typing.
     *
     * @event stop typing
     * @memberof SocketIOConnection
     * @param {Object} data - The stop typing event payload.
     * @param {string} data.chatId - The chat room ID.
     * @param {string} data.senderId - The user ID of the sender.
     * @example
     * socket.emit('stop typing', { chatId: '...', senderId: '...' });
     * // Other clients receive: socket.on('user stop typing', ...)
     */
    ConnectionSocket.on("stop typing", ({ chatId, senderId }) => {
      typingUsers.delete(`${chatId}: ${senderId}`)
      ConnectionSocket.broadcast.emit('user stop typing', {
        chatId, senderId
      })
    })

    /**
     * send_message event
     *
     * Sends a message to a friend. Validates friendship, emits to the chat room, and saves to DB after a delay.
     *
     * @event send_message
     * @memberof SocketIOConnection
     * @param {Object} data - The message payload.
     * @param {string} data.to - The recipient's user ID.
     * @param {string} data.text - The message text.
     * @example
     * socket.emit('send_message', { to: '<friend userId>', text: 'Hello!' });
     * // Other clients receive: socket.on('receive_message', ...)
     * @emits receive_message
     * @emits error
     */
    ConnectionSocket.on('send_message', async ({ to, text }) => {
      const room = createRoomName(userId, to);

      // 1. Validate friendship
      const sender = await User.findById(userId);
      const isFriend = sender.friends.some((id) => id.toString() === to);

      if (!isFriend) {
        return ConnectionSocket.emit('error', { message: "User is not your friend" });
      }

      // 2. Construct the message object
      const message = {
        from: userId,
        to,
        text,
        timestamp: new Date().toISOString(),
      };

      // 3. Emit to frontend immediately (real-time)
      io.to(room).emit('receive_message', message);
      // 4. Delay DB save (e.g., after 3 seconds)
      setTimeout(async () => {
        let chat = await Chat.findOne({
          participants: { $all: [userId, to], $size: 2 },
        });

        if (!chat) {
          chat = new Chat({
            participants: [userId, to],
            messages: [],
          });
        }

        chat.messages.push({
          sender: userId,
          text,
          timestamp: new Date(),
          status: 'sent',
        });

        await chat.save();
        console.log('💾 Message saved to DB');
      }, 3000); // Save after 3 seconds
    });

    /**
     * disconnect event
     *
     * Handles socket disconnection. Logs the disconnect and cleans up user state.
     *
     * @event disconnect
     * @memberof SocketIOConnection
     * @example
     * // Triggered automatically when the client disconnects
     */
    ConnectionSocket.on('disconnect', () => {
      console.log(`❌ Client disconnected: ${ConnectionSocket.id}`);
    });
  } catch (error) {
    console.error('JWT Error:', error);
    ConnectionSocket.disconnect(true);
  }
})

/**
 * Creates a unique room name for a chat between two users by sorting their user IDs and joining them with an underscore.
 *
 * Ensures that the room name is consistent regardless of the order of user IDs, so both users join the same room.
 *
 * @function createRoomName
 * @param {string} userId1 - The first user's ID.
 * @param {string} userId2 - The second user's ID.
 * @returns {string} The generated room name in the format 'userId1_userId2' (sorted).
 * @example
 * createRoomName('abc', 'xyz'); // returns 'abc_xyz'
 * createRoomName('xyz', 'abc'); // also returns 'abc_xyz'
 */
function createRoomName(userId1, userId2) {
  return [userId1, userId2].sort().join('_');
}

server.listen(3000, () => {
  console.log('Server running at http://localhost:3000');
});
