package mflix.api.controllers;

import com.sun.net.httpserver.Headers;
import mflix.api.models.Login;
import mflix.api.models.User;
import mflix.api.models.UserRegistry;
import mflix.api.services.MoviesService;
import mflix.api.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@SuppressWarnings("unchecked")
@CrossOrigin(origins = "*")
@RequestMapping(path = "api/v1/user")
@RestController
public class UserController extends ApiController {

  @Autowired UserService userService;

  @Autowired MoviesService moviesService;

  public UserController() {
    super();
  }

  private ResponseEntity buildSuccess(String authToken, User user) {
    Map response = new HashMap<String, Object>();
    response.put("auth_token", authToken);
    response.put("info", user);
    return ResponseEntity.ok(response);
  }

  @PostMapping("/login")
  public ResponseEntity authenticateUser(@RequestBody Login login) {

    System.out.println(login);
    Map<String, String> results = new HashMap<>();

    User user = userService.authenticate(login.getEmail(), login.getPassword(), results);
    if (user == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(results);
    }

    return buildSuccess(results.get("auth_token"), user);
  }

  @PostMapping("/register")
  public ResponseEntity register(@Valid @RequestBody UserRegistry register) {

    Map<String, String> results = new HashMap<>();

    User user = userService.createUser(register, results);
    if (user == null || user.isEmpty()) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(results);
    }

    return authenticateUser(new Login(register.getEmail(), register.getPassword()));
  }

  @PostMapping("/logout")
  public ResponseEntity logout(@NotNull @RequestHeader("Authorization") String logoutRequest) {
    String email = getEmailFromRequest(logoutRequest);

    if (userService.logoutUser(email)) {
      Map<String, String> response = new HashMap<>();
      response.put("status", "logged out");
      return ResponseEntity.ok(response);
    }

    return ResponseEntity.notFound().build();
  }

  @DeleteMapping("/delete")
  public ResponseEntity delete(
      @RequestHeader("Authorization") String authorizationToken,
      @NotNull @Size(min = 8) @RequestBody String password) {
    String email = getEmailFromRequest(authorizationToken);
    Map results = new HashMap<String, String>();
    if (!userService.deleteUser(email, password, results)) {
      return ResponseEntity.badRequest().body(results);
    }
    Map<String, String> response = new HashMap<>();
    response.put("success", "deleted");
    return ResponseEntity.ok(response);
  }

  @PutMapping("/update-preferences")
  public ResponseEntity updateUserPreferences(
      @RequestHeader("Authorization") String authorizationToken,
      @RequestBody Map<String, Object> userPreferences) {
    String email = getEmailFromRequest(authorizationToken);
    Map<String, Object> results = new HashMap<>();
    if (!userService.updateUserPreferences(email, userPreferences, results)) {
      results.put("status", "fail");
      return ResponseEntity.badRequest().body(results);
    }
    results.put("auth_token", tokenProvider.mintJWTHeader(email));
    return ResponseEntity.ok(results);
  }

  @PostMapping("/make-admin")
  public ResponseEntity makeUserAdmin(@RequestBody UserRegistry registry) {
    Map<String, String> results = new HashMap<>();
    User user = userService.createAdminUser(registry, results);

    if (user == null || user.isEmpty()) {
      results.put("status", "fail");
      return ResponseEntity.badRequest().body(results);
    }

    return authenticateUser(new Login(registry.getEmail(), registry.getPassword()));
  }

    @PostMapping("/adduser")
    public ResponseEntity adduser(@RequestBody UserRegistry registry) {
      Map<String, String> results = new HashMap<>();
      User user = userService.createUser(registry, results);

      if (user == null || user.isEmpty()) {
        results.put("status", "fail");
        return ResponseEntity.badRequest().body(results);
      }
      results.put("status", "success");
      return ResponseEntity.badRequest().body(results);
    }

  @PutMapping("/updateuser")
  public ResponseEntity updateuser(@RequestBody User user1) {
    Map<String, String> results = new HashMap<>();
    Boolean user = userService.updateUser(user1, results);

    if (user == false) {
      results.put("status", "fail");
      return ResponseEntity.badRequest().body(results);
    }
    results.put("status", "success");
    return ResponseEntity.badRequest().body(results);
  }




  @GetMapping("/comment-report")
  public ResponseEntity getCommentReport(
      @RequestHeader("Authorization") String authorizationToken) {
    String email = getEmailFromRequest(authorizationToken);
    Map<String, Object> results = new HashMap<>();
    User user = userService.loadUser(email);
    if (!user.isAdmin()) {
      results.put("status", "fail");
      return ResponseEntity.status(401).body(results);
    }

    results.put("auth_token", tokenProvider.mintJWTHeader(email));
    results.put("report", moviesService.mostActiveUsers());
    return ResponseEntity.ok(results);
  }


  @DeleteMapping("/deletebyusername")
  public ResponseEntity deletebyusername(
          @RequestParam(name= "user") String id) {
    Map results = new HashMap<String, String>();
    if (!userService.deleteUserByUser(id, results)) {
      return ResponseEntity.badRequest().body(results);
    }
    Map<String, String> response = new HashMap<>();
    response.put("success", "deleted");
    return ResponseEntity.ok(response);
  }

  @GetMapping("/getall")
  public ResponseEntity<List<User>> getall(){

    Map<String, String> response = new HashMap<>();
    return new ResponseEntity<>(userService.getall(), new HttpHeaders(), HttpStatus.OK);
  }


  @Override
  ResponseEntity<Map> index() {
    return ResponseEntity.ok(Collections.emptyMap());
  }
}
