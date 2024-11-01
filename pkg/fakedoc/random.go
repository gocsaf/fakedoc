// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2024 Intevation GmbH <https://intevation.de>

package fakedoc

import "math/rand/v2"

// choose returns a random element of choices. The element is chosen
// with uniform distribution. The choices slice must not be empty.
func choose[T any](rand *rand.Rand, choices []T) T {
	return choices[rand.IntN(len(choices))]
}
