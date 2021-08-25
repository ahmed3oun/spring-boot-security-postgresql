package com.spring.security.postgresql.controllers;

import java.io.UnsupportedEncodingException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.spring.security.postgresql.exception.TokenRefreshException;
import com.spring.security.postgresql.models.ERole;
import com.spring.security.postgresql.models.RefreshToken;
import com.spring.security.postgresql.models.Role;
import com.spring.security.postgresql.models.User;

import com.spring.security.postgresql.payload.request.ForgotPasswordRequest;
import com.spring.security.postgresql.payload.request.LogOutRequest;
import com.spring.security.postgresql.payload.request.LoginRequest;
import com.spring.security.postgresql.payload.request.ResetPasswordRequest;
import com.spring.security.postgresql.payload.request.SignupRequest;
import com.spring.security.postgresql.payload.request.TokenRefreshRequest;
import com.spring.security.postgresql.payload.response.JwtResponse;
import com.spring.security.postgresql.payload.response.MessageResponse;
import com.spring.security.postgresql.payload.response.TokenRefreshResponse;
import com.spring.security.postgresql.repository.RoleRepository;
import com.spring.security.postgresql.repository.UserRepository;
import com.spring.security.postgresql.security.jwt.JwtUtils;
import com.spring.security.postgresql.security.services.ForgotPasswordService;
import com.spring.security.postgresql.security.services.RefreshTokenService;
import com.spring.security.postgresql.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;

	@Autowired
	RefreshTokenService refreshTokenService;

	@Autowired
	ForgotPasswordService forgotPasswordServ;

	@Autowired
	JavaMailSender mailSender;

	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

	private static final String FRONT_URL = "http://localhost:4200";

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

		if (!userRepository.existsByUsername(loginRequest.getUsername())) {
			throw new RuntimeException(" This username does'nt exists !");
		}

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);

		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
		List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
				.collect(Collectors.toList());

		RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

		JwtResponse jwtResponse = new JwtResponse(jwt, refreshToken.getToken(), userDetails.getId(),
				userDetails.getUsername(), userDetails.getEmail(), roles);
		return ResponseEntity.ok(jwtResponse);
	}

	@PostMapping("/refreshtoken")
	public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
		String requestRefreshToken = request.getRefreshToken();

		return refreshTokenService.findByToken(requestRefreshToken).map(refreshTokenService::verifyExpiration)
				.map(RefreshToken::getUser).map(user -> {
					String token = jwtUtils.generateTokenFromUsername(user.getUsername());
					return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
				})
				.orElseThrow(() -> new TokenRefreshException(requestRefreshToken, "Refresh token is not in database!"));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
		}

		// Create new user's account
		User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();

		if (strRoles == null) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
					case "admin":
						Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
								.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
						roles.add(adminRole);

						break;

					default:
						Role userRole = roleRepository.findByName(ERole.ROLE_USER)
								.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
						roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);

		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}

	@PostMapping(value = "/logout", consumes = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> logoutUser(@RequestBody @Valid LogOutRequest logOutRequest) {
		refreshTokenService.deleteByUserId(logOutRequest.getUserId());
		return ResponseEntity.ok(new MessageResponse("Log out successful!"));
	}

	@PostMapping("/forgotPassword")
	public ResponseEntity<?> processForgotPassword(@Valid @RequestBody ForgotPasswordRequest request,
			HttpServletRequest req) throws MessagingException, UnsupportedEncodingException {
		String email = request.getEmail();
		User user = userRepository.findByEmail(email).get();
		String token = jwtUtils.generateTokenFromUsername(user.getUsername());

		try {
			forgotPasswordServ.updateResetPasswordToken(token, email);
			String resetPasswordLink = /* Utility.getSiteURL(req) */ FRONT_URL + "/resetPassword?token=" + token;
			MimeMessage message = mailSender.createMimeMessage();
			MimeMessageHelper helper = new MimeMessageHelper(message, true, "utf-8");
			helper.setTo(email);

			String subject = "Here's the link to reset your password";

			String content = "<p>Hello,</p>" + "<p>You have requested to reset your password.</p>"
					+ "<p>Click the link below to change your password:</p>" + "<p><a href=\"" + resetPasswordLink
					+ "\">Change my password</a></p>" + "<br>"
					+ "<p>Ignore this email if you do remember your password, "
					+ "or you have not made the request.</p>";
			helper.setText(content, true);
			helper.setSubject(subject);
			helper.setFrom("noreply@gmail.com");
			mailSender.send(message);

		} catch (MessagingException e) {
			logger.error("Exception raised while sending message to " + email, e);
		}
		return ResponseEntity
				.ok(new MessageResponse("We have sent a reset password link to your email. Please check."));

	}

	// api/auth/resetPassword?token=...
	@PostMapping("/resetPassword")
	public ResponseEntity<?> processResetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest,
			@RequestParam(required = true, value = "token") String token) {
		User user = forgotPasswordServ.getByResetPasswordToken(token);

		if (user == null) {
			return new ResponseEntity<MessageResponse>(new MessageResponse("Could not found user with token " + token),
					HttpStatus.NOT_FOUND);
		}

		if (resetPasswordRequest.getNewPassword().equals(resetPasswordRequest.getConfirmedPassword())) {
			user.setPassword(encoder.encode(resetPasswordRequest.getNewPassword()));
			userRepository.save(user);
			return ResponseEntity.ok(new MessageResponse("Password Changed Successfully ! Try to login again"));
		} else {
			throw new RuntimeException("Password is not confirmed ! Please confirm it");
		}

	}

	/*
	 * private void sendEmail(String recipientEmail, String link) throws
	 * UnsupportedEncodingException, MessagingException { MimeMessage message =
	 * mailSender.createMimeMessage(); MimeMessageHelper helper = new
	 * MimeMessageHelper(message);
	 * 
	 * helper.setFrom("contact@noreply.com", "personal");
	 * helper.setTo(recipientEmail);
	 * 
	 * String subject = "Here's the link to reset your password"; String content =
	 * "<p>Hello,</p>" + "<p>You have requested to reset your password.</p>" +
	 * "<p>Click the link below to change your password:</p>" + "<p><a href=\"" +
	 * link + "\">Change my password</a></p>" + "<br>" +
	 * "<p>Ignore this email if you do remember your password, " +
	 * "or you have not made the request.</p>";
	 * 
	 * helper.setSubject(subject); helper.setText(content, true);
	 * mailSender.send(message); }
	 */

}
