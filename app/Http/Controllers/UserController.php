<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\User;
use Illuminate\Support\Facades\Auth;
use Lcobucci\JWT\Parser;
use Symfony\Component\HttpFoundation\Response as ResponseHTTP;
use Validator;
/**
 * @OA\Info(
 *      version="1.0.0",
 *      title="L5 OpenApi",
 *      description="L5 Swagger OpenApi description",
 *      @OA\Contact(
 *          email="darius@matulionis.lt"
 *      ),
 *     @OA\License(
 *         name="Apache 2.0",
 *         url="http://www.apache.org/licenses/LICENSE-2.0.html"
 *     )
 * )
 */

/**
 * @OA\SecurityScheme(
 *     type="oauth2",
 *     description="Use a global client_id / client_secret and your username / password combo to obtain a token",
 *     name="Password Based",
 *     in="header",
 *     scheme="https",
 *     securityScheme="Password Based",
 *     @OA\Flow(
 *         flow="password",
 *         authorizationUrl="/oauth/authorize",
 *         tokenUrl="/oauth/token",
 *         refreshUrl="/oauth/token/refresh",
 *         scopes={}
 *     )
 * )
 */
/**
 * @OA\Tag(
 *     name="project",
 *     description="Everything about your Projects",
 *     @OA\ExternalDocumentation(
 *         description="Find out more",
 *         url="http://swagger.io"
 *     )
 * )
 *
 * @OA\Tag(
 *     name="user",
 *     description="用户相关接口",
 *     @OA\ExternalDocumentation(
 *         description="Find out more about",
 *         url="http://swagger.io"
 *     )
 * )
 * @OA\ExternalDocumentation(
 *     description="Find out more about Swagger",
 *     url="http://swagger.io"
 * )
 */

class AccountController extends Controller
{

/**
 * @OA\Get(
 *      path="/projects",
 *      operationId="getProjectsList",
 *      tags={"user"},
 *      summary="Get list of projects",
 *      description="Returns list of projects",
 *      @OA\Response(
 *          response=200,
 *          description="successful operation"
 *       ),
 *       @OA\Response(response=400, description="Bad request"),
 *       security={
 *           {"api_key_security_example": {}}
 *       }
 *     )
 *
 * Returns list of projects
 */
    /*
      login API

      @return \Illuminate\Http\Response
     */
    public function login(Request $request) {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required',
                'password' => 'required',
            ]);

            $data = [];

            if ($validator->fails()) {
                $errors = $validator->errors();
                foreach ($errors->all() as $field => $validationMessage) {
                    $data['error'][] = $validationMessage;
                }
                $success = [
                    'status' => ResponseHTTP::HTTP_BAD_REQUEST,
                    'data' => $data
                ];
                $message = 'Validation failed!.';
            } else {
                if (Auth::guard()->attempt(['email' => request('email'), 'password' => request('password')])) {
                    $user = Auth::user()->select('id', 'first_name', 'last_name', 'email', 'avatar', 'referral_code')->where('id', Auth::id())->get()->first();

                    $data['token'] = $user->createToken('MyApp')->accessToken;
                    $data['user'] = $user;

                    $success = [
                        'status' => ResponseHTTP::HTTP_OK ,
                        'data' => $data,
                    ];

                    $message = 'Login successfull!.';

                    //store device information
                    UserDevice::addUserDevices($request, $user, config('constants.status.active'));
                } else {
                    $success = [
                        'status' => ResponseHTTP::HTTP_BAD_REQUEST ,
                    ];
                    $message = 'Invalid Email or Password!.';

                }
            }

            return $this->APIResponse->respondWithMessageAndPayload($success ,$message);
        } catch (\Exception $e) {
            return $this->APIResponse->handleAndResponseException($e);
        }
    }
}

