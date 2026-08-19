-module(oidcc_client_context_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jws.hrl").
-include_lib("jose/include/jose_jwt.hrl").
-include_lib("oidcc/include/oidcc_client_context.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").

provider_not_running_test() ->
    ?assertMatch(
        {error, provider_not_ready},
        oidcc_client_context:from_configuration_worker(
            invalid,
            <<"client_id">>,
            <<"client_secret">>
        )
    ),
    ok.

from_configuration_worker_registered_name_uses_ets_test() ->
    ok = meck:new(httpc, [no_link]),
    DiscoveryBody = jsx:encode(#{
        issuer => <<"https://example.com">>,
        jwks_uri => <<"https://example.com/keys">>,
        authorization_endpoint => <<"https://example.com/authorize">>,
        scopes_supported => [<<"openid">>],
        response_types_supported => [<<"code">>],
        subject_types_supported => [<<"public">>],
        id_token_signing_alg_values_supported => [<<"RS256">>]
    }),
    HttpFun =
        fun
            (
                get,
                {"https://example.com/.well-known/openid-configuration", []},
                _HttpOpts,
                _Opts,
                _Profile
            ) ->
                {ok, {
                    {"HTTP/1.1", 200, "OK"},
                    [{"content-type", "application/json"}],
                    DiscoveryBody
                }};
            (
                get,
                {<<"https://example.com/keys">>, []},
                _HttpOpts,
                _Opts,
                _Profile
            ) ->
                {ok, {
                    {"HTTP/1.1", 200, "OK"},
                    [{"content-type", "application/json"}],
                    jsx:encode(#{keys => []})
                }}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    WorkerName = from_configuration_worker_registered_name_uses_ets_test,
    try
        {ok, WorkerPid} =
            oidcc_provider_configuration_worker:start_link(#{
                issuer => <<"https://example.com">>,
                name => {local, WorkerName}
            }),

        %% Wait for the worker to load both values into its ETS table.
        ?assertMatch(
            #oidcc_provider_configuration{issuer = <<"https://example.com">>},
            wait_until(fun() ->
                oidcc_provider_configuration_worker:get_provider_configuration(WorkerName)
            end)
        ),
        ?assertMatch(
            #jose_jwk{keys = {jose_jwk_set, []}},
            wait_until(fun() ->
                oidcc_provider_configuration_worker:get_jwks(WorkerName)
            end)
        ),

        %% A suspended worker cannot answer gen_server calls; the registered-name
        %% API must use the ETS fast path and return immediately.
        ok = sys:suspend(WorkerPid),

        {ElapsedUs, Result} = timer:tc(fun() ->
            oidcc_client_context:from_configuration_worker(
                WorkerName,
                <<"client_id">>,
                <<"client_secret">>
            )
        end),

        ?assertMatch({ok, #oidcc_client_context{}}, Result),
        ?assert(ElapsedUs < 1_000_000)
    after
        stop_worker(WorkerName),
        meck:unload(httpc)
    end.

apply_profiles_fapi2_security_profile_test() ->
    ClientContext0 = client_context_fixture(),
    Opts0 = #{
        profiles => [fapi2_security_profile]
    },

    ProfileResult = oidcc_client_context:apply_profiles(ClientContext0, Opts0),

    ?assertMatch(
        {ok, #oidcc_client_context{}, #{}},
        ProfileResult
    ),

    {ok, ClientContext, Opts} = ProfileResult,

    ?assertMatch(
        #oidcc_client_context{
            provider_configuration = #oidcc_provider_configuration{
                response_types_supported = [<<"code">>],
                id_token_signing_alg_values_supported = [<<"EdDSA">>],
                userinfo_signing_alg_values_supported = [
                    <<"PS256">>,
                    <<"PS384">>,
                    <<"PS512">>,
                    <<"ES256">>,
                    <<"ES384">>,
                    <<"ES512">>,
                    <<"EdDSA">>
                ],
                code_challenge_methods_supported = [<<"S256">>],
                require_pushed_authorization_requests = true,
                authorization_response_iss_parameter_supported = true
            }
        },
        ClientContext
    ),

    ?assertMatch(
        #{
            preferred_auth_methods := [private_key_jwt, tls_client_auth],
            require_pkce := true,
            trusted_audiences := [],
            request_opts := #{
                ssl := _
            }
        },
        Opts
    ),

    #{request_opts := #{ssl := SslOpts}} = Opts,

    ?assertEqual(
        {ciphers, [
            #{
                cipher => 'aes_128_gcm',
                mac => aead,
                key_exchange => dhe_rsa,
                prf => sha256
            },
            #{
                cipher => 'aes_128_gcm',
                mac => aead,
                key_exchange => ecdhe_rsa,
                prf => sha256
            },
            #{
                cipher => 'aes_256_gcm',
                mac => aead,
                key_exchange => dhe_rsa,
                prf => sha384
            },
            #{
                cipher => 'aes_256_gcm',
                mac => aead,
                key_exchange => ecdhe_rsa,
                prf => sha384
            }
        ]},
        lists:keyfind(ciphers, 1, SslOpts)
    ),

    ?assertEqual(
        {verify, verify_peer},
        lists:keyfind(verify, 1, SslOpts)
    ),

    ?assertMatch(
        {cacerts, _},
        lists:keyfind(cacerts, 1, SslOpts)
    ),

    ok.

apply_profiles_fapi2_message_signing_test() ->
    ClientContext0 = client_context_fixture(),
    Opts0 = #{
        profiles => [fapi2_message_signing]
    },

    ProfileResult = oidcc_client_context:apply_profiles(ClientContext0, Opts0),

    ?assertMatch(
        {ok, #oidcc_client_context{}, #{}},
        ProfileResult
    ),

    {ok, ClientContext, Opts} = ProfileResult,

    ?assertMatch(
        #oidcc_client_context{
            provider_configuration = #oidcc_provider_configuration{
                response_types_supported = [<<"code">>],
                response_modes_supported = [<<"jwt">>, <<"query.jwt">>],
                id_token_signing_alg_values_supported = [<<"EdDSA">>],
                userinfo_signing_alg_values_supported = [
                    <<"PS256">>,
                    <<"PS384">>,
                    <<"PS512">>,
                    <<"ES256">>,
                    <<"ES384">>,
                    <<"ES512">>,
                    <<"EdDSA">>
                ],
                code_challenge_methods_supported = [<<"S256">>],
                require_pushed_authorization_requests = true,
                authorization_response_iss_parameter_supported = true
            }
        },
        ClientContext
    ),

    ?assertMatch(
        #{
            preferred_auth_methods := [private_key_jwt, tls_client_auth],
            require_pkce := true,
            trusted_audiences := [],
            request_opts := #{
                ssl := _
            }
        },
        Opts
    ),

    ok.

apply_profiles_mtls_constrain_test() ->
    ClientContext0 = client_context_fixture(),
    Opts0 = #{
        profiles => [mtls_constrain]
    },

    ProfileResult = oidcc_client_context:apply_profiles(ClientContext0, Opts0),

    ?assertMatch(
        {ok, #oidcc_client_context{}, #{}},
        ProfileResult
    ),

    {ok, ClientContext, Opts} = ProfileResult,

    ?assertMatch(
        #oidcc_client_context{
            provider_configuration = #oidcc_provider_configuration{
                token_endpoint = <<"https://my.provider/tls/token">>,
                userinfo_endpoint = <<"https://my.provider/tls/userinfo">>
            }
        },
        ClientContext
    ),

    ?assertEqual(
        #{},
        Opts
    ),

    ok.

apply_profiles_fapi2_connectid_au_test() ->
    ClientContext0 = client_context_fixture(),
    Opts0 = #{
        profiles => [fapi2_connectid_au]
    },

    ProfileResult = oidcc_client_context:apply_profiles(ClientContext0, Opts0),

    ?assertMatch(
        {ok, #oidcc_client_context{}, #{}},
        ProfileResult
    ),

    {ok, ClientContext, Opts} = ProfileResult,

    ?assertMatch(
        #oidcc_client_context{
            provider_configuration = #oidcc_provider_configuration{
                token_endpoint = <<"https://my.provider/tls/token">>,
                userinfo_endpoint = <<"https://my.provider/tls/userinfo">>,
                response_types_supported = [<<"code">>],
                response_modes_supported = [<<"jwt">>, <<"query.jwt">>],
                id_token_signing_alg_values_supported = [<<"EdDSA">>],
                userinfo_signing_alg_values_supported = [
                    <<"PS256">>,
                    <<"PS384">>,
                    <<"PS512">>,
                    <<"ES256">>,
                    <<"ES384">>,
                    <<"ES512">>,
                    <<"EdDSA">>
                ],
                code_challenge_methods_supported = [<<"S256">>],
                require_pushed_authorization_requests = true,
                pushed_authorization_request_endpoint = undefined,
                authorization_response_iss_parameter_supported = true
            }
        },
        ClientContext
    ),

    ?assertMatch(
        #{
            preferred_auth_methods := [private_key_jwt, tls_client_auth],
            require_pkce := true,
            require_purpose := true,
            trusted_audiences := [],
            request_opts := #{
                ssl := _
            }
        },
        Opts
    ),

    ok.

apply_profiles_unknown_test() ->
    ClientContext = client_context_fixture(),
    Opts = #{
        profiles => [unknown]
    },

    ?assertMatch(
        {error, {unknown_profile, unknown}},
        oidcc_client_context:apply_profiles(ClientContext, Opts)
    ),

    ok.

client_context_fixture() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/fapi2-metadata.json"),
    {ok, #oidcc_provider_configuration{} = Configuration} =
        oidcc_provider_configuration:decode_configuration(jose:decode(ConfigurationBinary)),

    Jwks = jose_jwk:from_pem_file(PrivDir ++ "/test/fixtures/jwk-ed25519.pem"),

    ClientId = <<"client_id">>,
    ClientSecret = <<"client_secret">>,

    oidcc_client_context:from_manual(Configuration, Jwks, ClientId, ClientSecret).

stop_worker(WorkerName) ->
    case erlang:whereis(WorkerName) of
        undefined ->
            ok;
        WorkerPid ->
            gen_server:stop(WorkerPid)
    end.

wait_until(Fun) ->
    wait_until(Fun, 20).

wait_until(Fun, 0) ->
    Fun();
wait_until(Fun, Retries) ->
    case Fun() of
        undefined ->
            timer:sleep(50),
            wait_until(Fun, Retries - 1);
        Value ->
            Value
    end.
