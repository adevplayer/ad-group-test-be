<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
	public function register(Request $request)
	{
		return User::create([
			'name' => $request->input(key: 'name'),
			'email' => $request->input(key: 'email'),
			'ip' => $request->input(key: 'ip'),
			'ip_label' => $request->input(key: 'ip_label'),
			'password' => Hash::make($request->input(key: 'password')),
		]);
	}

	public function login(Request $request)
	{
		if (!Auth::attempt($request->only('email', 'password'))) {
			return response([
				'message' => 'Invalid credentials!'
			], Response::HTTP_UNAUTHORIZED);
		}

		$user = Auth::user();
		$token = $user->createToken('token')->plainTextToken;
		$cookie = cookie('jwt', $token, 60 * 24); // 24 hours

		return response([
			'message' => 'Success!'
		])->withCookie($cookie);
	}

	public function user()
	{
		return Auth::user();
	}
}
