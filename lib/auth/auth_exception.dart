import 'package:custom_services/services/crash_report/logger.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

enum AuthExceptionType {
  UNCLASSIFIED,
  WEAK_PASSWORD,
  EMAIL_IN_USE,
  CREDENTIAL_IN_USE,
  USER_NOT_EXISTS,
  PASSWORD_WRONG,
  ACC_EXISTS_WITH_OTHER_CRED,
  PLATFORM_ERROR,
  NOT_COMPLETED,
  TOO_MANY_REQUESTS,
  INVALID_CREDENTIAL,
  RECENT_LOGIN_REQUIRED,
  REQUEST_ERROR
}

class AuthException {
  final AuthExceptionType type;
  final dynamic error;

  AuthException(this.type, {this.error});

  static AuthException from(Object err, {String method = ''}) {
    if (err is FirebaseAuthException) {
      switch (_code(err)) {
        case 'weak-password':
          return AuthException(AuthExceptionType.WEAK_PASSWORD);
        case 'email-already-in-use':
          return AuthException(AuthExceptionType.EMAIL_IN_USE);
        case 'credential-already-in-use':
          return AuthException(AuthExceptionType.CREDENTIAL_IN_USE);
        case 'user-not-found':
          return AuthException(AuthExceptionType.USER_NOT_EXISTS);
        case 'wrong-password':
          return AuthException(AuthExceptionType.PASSWORD_WRONG);
        case 'too-many-requests':
          return AuthException(AuthExceptionType.TOO_MANY_REQUESTS);
        case 'account-exists-with-different-credential':
          return AuthException(AuthExceptionType.ACC_EXISTS_WITH_OTHER_CRED);
        case 'invalid-credential':
          return AuthException(AuthExceptionType.INVALID_CREDENTIAL);
        case 'popup-closed-by-user':
          return AuthException(AuthExceptionType.NOT_COMPLETED);
        case 'requires-recent-login':
          return AuthException(AuthExceptionType.RECENT_LOGIN_REQUIRED);
        case 'network-request-failed':
          return AuthException(AuthExceptionType.REQUEST_ERROR);
        default:
          ServiceLogger.instance.error(
            module: AuthException,
            message: 'Unhandled code on signin with $method: ${err.code}',
          );

          return AuthException(AuthExceptionType.UNCLASSIFIED, error: err);
      }
    } else if (err is SignInWithAppleAuthorizationException) {
      return AuthException(AuthExceptionType.NOT_COMPLETED);
    } else {
      ServiceLogger.instance.error(
        module: AuthException,
        message: 'Unexpected error on signin with $method: $err',
      );

      return AuthException(AuthExceptionType.UNCLASSIFIED, error: err);
    }
  }

  @override
  String toString() {
    String result = type.name;
    if (error != null) {
      result += ': $error';
    }
    return result;
  }

  static String _code(FirebaseAuthException err) {
    if (err.code == 'unknown') {
      //  In web the code is delivered as unknown but real code is in message
      //  e.g.:
      //  An unknown error occurred: FirebaseError: Firebase: The email address
      //  is already in use by another account. (auth/email-already-in-use).
      var regex = RegExp('.*\\(auth\\/|\\).\$');
      var code = err.message?.replaceAll(regex, '') ?? '';
      if (code.isNotEmpty) {
        return code;
      }
    }

    return err.code;
  }
}
