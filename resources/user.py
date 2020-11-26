from blacklist import BLACKLIST
from flask_jwt_extended.utils import get_jwt_identity, get_raw_jwt
from flask_jwt_extended.view_decorators import jwt_refresh_token_required, jwt_required
from flask_restful import Resource, reqparse
from models.user import UserModel
from werkzeug.security import safe_str_cmp
from flask_jwt_extended import create_access_token, create_refresh_token


class UserRegister(Resource):
    req_parse = reqparse.RequestParser()
    req_parse.add_argument('username', type=str,
                           required=True, help='This field cannot be blank!')
    req_parse.add_argument('password', type=str,
                           required=True, help='This field cannot be blank!')

    def post(self):
        data = UserRegister.req_parse.parse_args()

        if UserModel.find_by_username(data['username']):
            return {'message': 'A user with that username already exists'}, 400

        user = UserModel(**data)
        user.save_to_db()

        return {"message": "User created successfully."}, 201


class User(Resource):
    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'User not found'}, 404
        return user.json()

    @classmethod
    def delete(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message', 'User not found'}, 404
        user.delete_from_db()
        return {'message': 'User deleted.'}, 204


class UserLogin(Resource):
    req_parse = reqparse.RequestParser()
    req_parse.add_argument('username', type=str,
                           required=True, help='This field cannot be blank!')
    req_parse.add_argument('password', type=str,
                           required=True, help='This field cannot be blank!')

    @classmethod
    def post(cls):
        data = cls.req_parse.parse_args()

        user = UserModel.find_by_username(data['username'])

        if user and safe_str_cmp(user.password, data['password']):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {
                'access_token': access_token,
                'refresh_token': refresh_token
            }, 200

        return {'message': 'Invalid credentials'}, 401


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {'access_token': new_token}


class UserLogout(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        BLACKLIST.add(jti)
        return {'message': 'Successfully logout.'}
