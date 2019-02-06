package onelogin

import (
	"fmt"

	"golang.org/x/net/context"
)

// RoleService deals with OneLogin roles.
type RoleService struct {
	*service
}

type Role struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// GetRoles returns all the OneLogin Roles.
func (s *RoleService) GetRoles(ctx context.Context) ([]*Role, error) {
	u := "/api/1/roles"

	var roles []*Role
	var afterCursor string

	for {
		uu, err := addOptions(u, &urlQuery{AfterCursor: afterCursor})
		if err != nil {
			return nil, err
		}

		req, err := s.client.NewRequest("GET", uu, nil)
		if err != nil {
			return nil, err
		}

		if err := s.client.AddAuthorization(ctx, req); err != nil {
			return nil, err
		}

		var rs []*Role
		resp, err := s.client.Do(ctx, req, &rs)
		if err != nil {
			return nil, err
		}
		roles = append(roles, rs...)
		if resp.PaginationAfterCursor == nil {
			break
		}

		afterCursor = *resp.PaginationAfterCursor
	}

	return roles, nil
}

// GetRole returns a OneLogin role specified by its ID.
func (s *RoleService) GetRole(ctx context.Context, id int64) (*Role, error) {
	u := fmt.Sprintf("/api/1/roles/%v", id)

	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	if err := s.client.AddAuthorization(ctx, req); err != nil {
		return nil, err
	}

	var roles []*Role
	_, err = s.client.Do(ctx, req, &roles)
	if err != nil {
		return nil, err
	}

	return roles[0], nil
}
