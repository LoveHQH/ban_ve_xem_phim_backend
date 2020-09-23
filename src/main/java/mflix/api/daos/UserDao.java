package mflix.api.daos;

import com.mongodb.DuplicateKeyException;
import com.mongodb.MongoClientSettings;
import com.mongodb.WriteConcern;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.InsertOneOptions;
import com.mongodb.client.model.UpdateOptions;
import com.mongodb.client.result.UpdateResult;
import mflix.api.models.Comment;
import mflix.api.models.Session;
import mflix.api.models.User;
import org.bson.BsonDocument;
import org.bson.Document;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.codecs.pojo.PojoCodecProvider;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static com.mongodb.client.model.Filters.eq;
import static com.mongodb.client.model.Updates.set;
import static org.bson.codecs.configuration.CodecRegistries.fromProviders;
import static org.bson.codecs.configuration.CodecRegistries.fromRegistries;

@Configuration
public class UserDao extends AbstractMFlixDao{
    
    private final MongoCollection<User> usersCollection;
    //DONE> Ticket: User Management - do the necessary changes so that the sessions collection
    //returns a Session object
    private final MongoCollection<Session> sessionsCollection;
    
    private final Logger log;
    
    @Autowired
    public UserDao(
            MongoClient mongoClient, @Value("${spring.mongodb.database}") String databaseName) {
        super(mongoClient, databaseName);
        CodecRegistry pojoCodecRegistry =
                fromRegistries(
                        MongoClientSettings.getDefaultCodecRegistry(),
                        fromProviders(PojoCodecProvider.builder().automatic(true).build()));
        
        usersCollection = db.getCollection("users", User.class).withCodecRegistry(pojoCodecRegistry);
        log = LoggerFactory.getLogger(this.getClass());
        //DONE> Ticket: User Management - implement the necessary changes so that the sessions
        // collection returns a Session objects instead of Document objects.
        sessionsCollection = db.getCollection("sessions", Session.class).withCodecRegistry(pojoCodecRegistry);
    }
    
    /**
     * Inserts the `user` object in the `users` collection.
     *
     * @param user - User object to be added
     * @return True if successful, throw IncorrectDaoOperation otherwise
     */
    public boolean addUser(User user) {
        //DONE > Ticket: Durable Writes -  you might want to use a more durable write concern here!
        usersCollection.withWriteConcern(WriteConcern.MAJORITY);
        //DONE > Ticket: Handling Errors - make sure to only add new users
        // and not users that already exist.
        User check = getUser(user.getEmail());

        if ( Objects.nonNull(check) && check.getEmail() == user.getEmail()) {
            throw new IncorrectDaoOperation("User already exists.");
        }
        usersCollection.insertOne(user);
        return true;
    }
    
    /**
     * Creates session using userId and jwt token.
     *
     * @param userId - user string identifier
     * @param jwt    - jwt string token
     * @return true if successful
     */
    public boolean createUserSession(String userId, String jwt) {
        //DONE> Ticket: User Management - implement the method that allows session information to be
        // stored in it's designated collection.
        Session session = new Session();
        session.setUserId(userId);
        session.setJwt(jwt);
        
        Document queryFilter = new Document();
        queryFilter.put("user_id", userId);
        
        if (sessionsCollection.find(queryFilter).iterator().hasNext()) {
            deleteUserSessions(userId);
        }
        
        sessionsCollection.insertOne(session);
        return true;
        //DONE > Ticket: Handling Errors - implement a safeguard against
        // creating a session with the same jwt token.
    }
    
    /**
     * Returns the User object matching the an email string value.
     *
     * @param email - email string to be matched.
     * @return User object or null.
     */
    public User getUser(String email) {
        User user = null;
        //DONE> Ticket: User Management - implement the query that returns the first User object.
        Document queryFilter = new Document("email", email);
        user = usersCollection.find(queryFilter).first();
        return user;
    }


    public User getUserbyId(String id) {
        User user = null;
        //DONE> Ticket: User Management - implement the query that returns the first User object.
        Document queryFilter = new Document("user_id", id);
        user = usersCollection.find(queryFilter).first();
        return user;
    }
    
    /**
     * Given the userId, returns a Session object.
     *
     * @param userId - user string identifier.
     * @return Session object or null.
     */
    public Session getUserSession(String userId) {
        //DONE> Ticket: User Management - implement the method that returns Sessions for a given
        // userId
        Session session = new Session();
        
        Document queryFilter = new Document("user_id", userId);
        session = sessionsCollection.find(queryFilter).first();
        
        return session;
    }
    
    public boolean deleteUserSessions(String userId) {
        //DONE> Ticket: User Management - implement the delete user sessions method
        Document queryFilter = new Document();
        queryFilter.put("user_id", userId);
        
        sessionsCollection.deleteMany(queryFilter);
        
        return true;
    }
    
    /**
     * Removes the user document that match the provided email.
     *
     * @param email - of the user to be deleted.
     * @return true if user successfully removed
     */
    public boolean deleteUser(String email) {
        // remove user sessions
        //DONE> Ticket: User Management - implement the delete user method
        //DONE > Ticket: Handling Errors - make this method more robust by
        // handling potential exceptions.
        Document queryFilter = new Document();
        queryFilter.put("email", email);
        
        usersCollection.deleteOne(queryFilter);
        deleteUserSessions(email);
        
        return true;
    }
    
    /**
     * Updates the preferences of an user identified by `email` parameter.
     *
     * @param email           - user to be updated email
     * @param userPreferences - set of preferences that should be stored and replace the existing
     *                        ones. Cannot be set to null value
     * @return User object that just been updated.
     */
    public boolean updateUserPreferences(String email, Map<String, ?> userPreferences) {
        //DONE> Ticket: User Preferences - implement the method that allows for user preferences to
        // be updated.
        //DONE > Ticket: Handling Errors - make this method more robust by
        // handling potential exceptions when updating an entry.
        
        Document queryFilter = new Document("email", email);
        Document userPref = new Document();
        
        if (userPreferences == null || userPreferences.isEmpty()) {
            throw new IncorrectDaoOperation("Preferences can not be empty or null.", new Throwable());
        }
        
        for (String key : userPreferences.keySet()) {
            userPref.put(key, userPreferences.get(key).toString());
        }
        
        usersCollection.updateOne(eq("email", email), set("preferences", userPref),
                new UpdateOptions().upsert(true));
        
        
        return true;
    }

    public List<User> getall(){

        List<User> users = new ArrayList<>();

        usersCollection
                .find()
                .iterator()
                .forEachRemaining(users::add);

        return users;
    }

    public boolean updateUser(User user1) {
        Bson queryFilter = Filters.and(
                Filters.eq("email", user1.getEmail())
        );
        User user2 = usersCollection.find(queryFilter).first();
        if (user2 != null) {
            UpdateResult updateResult = usersCollection.updateOne(queryFilter, set("name", user1.getName()));
            return updateResult.wasAcknowledged();
        }
        return false;
    }

}