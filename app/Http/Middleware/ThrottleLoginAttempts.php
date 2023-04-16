<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter as FacadesRateLimiter;
use Symfony\Component\HttpFoundation\Response;

class ThrottleLoginAttempts
{
    public function handle(Request $request, Closure $next, $maxAttempts = 3, $decayMinutes = 0.5)
    {
        $key = $this->resolveRequestSignature($request);

        $limiter = FacadesRateLimiter::for('login', [
            'key' => $key,
            'maxAttempts' => $maxAttempts,
            'decayMinutes' => $decayMinutes,
        ]);

        if ($limiter->tooManyAttempts($key)) {
            $retryAfter = $limiter->availableIn($key);
            return response()->json([
                'message' => 'Too many login attempts. Please try again in ' . $retryAfter . ' seconds.'
            ], Response::HTTP_TOO_MANY_REQUESTS);
        }

        $limiter->hit($key);

        $response = $next($request);

        if ($response->getStatusCode() === Response::HTTP_UNAUTHORIZED) {
            $limiter->hit($key);
        }

        return $response;
    }

    protected function resolveRequestSignature($request)
    {
        return sha1(
            $request->method() .
            '|' . $request->server('SERVER_NAME') .
            '|' . $request->path() .
            '|' . $request->ip()
        );
    }
}
