/*
Copyright (C) 2022 Jake Sanders

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package authn

import (
	"context"
	"errors"

	"github.com/bufbuild/connect-go"
)

func StaticTokenInterceptor(token string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			authToken := req.Header().Get("Authorization")
			if authToken != token {
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("invalid token"))
			}
			res, err := next(ctx, req)
			if err != nil {
				return nil, err
			}
			return res, nil
		})
	}
}
