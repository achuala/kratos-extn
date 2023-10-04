package extn

import (
	"context"
	"net/http"
	"time"

	kjson "github.com/go-kratos/kratos/v2/encoding/json"
	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/google/uuid"
	"go.opentelemetry.io/contrib/propagators/b3"
	"google.golang.org/protobuf/encoding/protojson"

	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/middleware/tracing"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
)

type CtxKey string

const CtxCorrelationIdKey = CtxKey("x-correlation-id")
const CtxSystemPeerKey = CtxKey("x-system-peer")
const CtxSignedHeadersKey = CtxKey("x-signed-headers")
const CtxAuthorizationKey = CtxKey("Authorization")

func getCorrelationIdFromCtx(ctx context.Context) string {
	correlationId := ctx.Value(CtxCorrelationIdKey)
	if correlationId == nil {
		return uuid.NewString()
	}
	return correlationId.(string)
}

func ClientCorrelationIdInjector() middleware.Middleware {

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			if tr, ok := transport.FromClientContext(ctx); ok {
				tr.RequestHeader().Set(string(CtxCorrelationIdKey), getCorrelationIdFromCtx(ctx))
			}
			return handler(ctx, req)
		}
	}
}

func ServerCorrelationIdInjector() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			if tr, ok := transport.FromServerContext(ctx); ok {
				correlationId := tr.RequestHeader().Get(string(CtxCorrelationIdKey))
				ctx = transport.NewServerContext(context.WithValue(ctx, CtxCorrelationIdKey, correlationId), tr)
			}
			return handler(ctx, req)
		}
	}
}

func ServerSecurityHeaderValidator() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			if tr, ok := transport.FromServerContext(ctx); ok {
				authHeader := tr.RequestHeader().Get(string(CtxAuthorizationKey))
				signatureHeader := tr.RequestHeader().Get(string(CtxSignedHeadersKey))
				if len(authHeader) == 0 || len(signatureHeader) == 0 {
					return nil, errors.Unauthorized("UNAUTHORIZED", "Missing authorization/signature headers")
				}
			}
			return handler(ctx, req)
		}
	}
}

func NewHttpClient(ctx context.Context, endpoint string, logger log.Logger) (*khttp.Client, error) {
	kjson.MarshalOptions = protojson.MarshalOptions{
		UseProtoNames: true,
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxConnsPerHost = 200
	t.MaxIdleConnsPerHost = 100
	b3Propagator := b3.New(b3.WithInjectEncoding(b3.B3MultipleHeader | b3.B3SingleHeader))
	httpClient, err := khttp.NewClient(ctx, khttp.WithEndpoint(endpoint), khttp.WithMiddleware(
		recovery.Recovery(),
		tracing.Client(tracing.WithPropagator(b3Propagator)),
		ClientCorrelationIdInjector(),
		Client(logger),
	), khttp.WithTimeout(time.Second*10), khttp.WithTransport(t))

	if err != nil {
		log.With(logger).Log(log.LevelError, "failed to initialize http client", err)
		return nil, err
	}
	return httpClient, nil
}

func DoPost[T any](ctx context.Context, hc *khttp.Client, url string, headers map[string]string, body io.Reader, responseType T) (T, error) {
	return MakeHTTPRequest(ctx, hc, url, http.MethodPost, headers, make(map[string][]string, 0), body, responseType)
}

// in the case of GET, the parameter queryParameters is transferred to the URL as query parameters
// in the case of POST, the parameter body, an io.Reader, is used
func MakeHTTPRequest[T any](ctx context.Context, hc *khttp.Client, fullUrl string, httpMethod string, headers map[string]string, queryParameters url.Values, body io.Reader, responseType T) (T, error) {
	u, err := url.Parse(fullUrl)
	if err != nil {
		return responseType, err
	}

	// if it's a GET, we need to append the query parameters.
	if httpMethod == "GET" {
		q := u.Query()

		for k, v := range queryParameters {
			// this depends on the type of api, you may need to do it for each of v
			q.Set(k, strings.Join(v, ","))
		}
		// set the query to the encoded parameters
		u.RawQuery = q.Encode()
	}

	// regardless of GET or POST, we can safely add the body
	req, err := http.NewRequestWithContext(ctx, httpMethod, u.String(), body)
	if err != nil {
		return responseType, err
	}

	// for each header passed, add the header value to the request
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// finally, do the request
	res, err := hc.Do(req)
	if err != nil {
		return responseType, err
	}

	if res == nil {
		return responseType, fmt.Errorf("error: calling %s returned empty response", u.String())
	}

	responseData, err := io.ReadAll(res.Body)
	if err != nil {
		return responseType, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return responseType, fmt.Errorf("error calling %s:\nstatus: %s\nresponseData: %s", u.String(), res.Status, responseData)
	}

	var responseObject T
	err = json.Unmarshal(responseData, &responseObject)

	if err != nil {
		return responseType, err
	}

	return responseObject, nil
}
