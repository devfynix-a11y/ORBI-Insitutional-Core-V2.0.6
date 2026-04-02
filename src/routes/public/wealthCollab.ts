const normalizeWealthIdentifier = (value: string) => value.trim().toLowerCase();

const normalizeWealthPhone = (value: string) =>
  value
    .trim()
    .replace(/[^\d+]/g, '')
    .replace(/(?!^)\+/g, '');

const isEmailLikeIdentifier = (value: string) => value.includes('@');

export const resolveSharedPotMembership = async (sb: any, potId: string, userId: string) => {
  const { data: pot, error: potError } = await sb
    .from('shared_pots')
    .select('*')
    .eq('id', potId)
    .maybeSingle();
  if (potError) throw new Error(potError.message);
  if (!pot) throw new Error('SHARED_POT_NOT_FOUND');

  const { data: membership, error: memberError } = await sb
    .from('shared_pot_members')
    .select('*')
    .eq('pot_id', potId)
    .eq('user_id', userId)
    .maybeSingle();
  if (memberError) throw new Error(memberError.message);

  const ownerMembership = pot.owner_user_id === userId
    ? { role: 'OWNER', user_id: userId, pot_id: potId }
    : null;

  const effectiveMembership = membership || ownerMembership;
  if (!effectiveMembership) throw new Error('SHARED_POT_ACCESS_DENIED');
  return { pot, membership: effectiveMembership };
};

export const canManageSharedPot = (role: string) => ['OWNER', 'MANAGER'].includes(role.toUpperCase());
export const canContributeToSharedPot = (role: string) =>
  ['OWNER', 'MANAGER', 'CONTRIBUTOR'].includes(role.toUpperCase());

export const resolveUserBySharedPotIdentifier = async (sb: any, identifier: string) => {
  if (isEmailLikeIdentifier(identifier)) {
    const { data, error } = await sb
      .from('users')
      .select('id,email,phone,full_name')
      .eq('email', normalizeWealthIdentifier(identifier))
      .maybeSingle();
    if (error) throw new Error(error.message);
    return data;
  }

  const normalizedPhone = normalizeWealthPhone(identifier);
  const candidates = Array.from(new Set([identifier.trim(), normalizedPhone, normalizedPhone.replace(/\D/g, '')].filter(Boolean)));
  const { data, error } = await sb
    .from('users')
    .select('id,email,phone,full_name')
    .in('phone', candidates)
    .limit(1)
    .maybeSingle();
  if (error) throw new Error(error.message);
  return data;
};

export const expireSharedPotInvitationIfNeeded = async (sb: any, invite: any) => {
  if (!invite?.expires_at) return invite;
  if (String(invite.status || '').toUpperCase() !== 'PENDING') return invite;
  if (new Date(invite.expires_at).getTime() > Date.now()) return invite;

  const { data, error } = await sb
    .from('shared_pot_invitations')
    .update({
      status: 'EXPIRED',
      updated_at: new Date().toISOString(),
    })
    .eq('id', invite.id)
    .select('*')
    .single();
  if (error) throw new Error(error.message);
  return data || invite;
};

export const resolveSharedBudgetMembership = async (sb: any, budgetId: string, userId: string) => {
  const { data: budget, error: budgetError } = await sb
    .from('shared_budgets')
    .select('*')
    .eq('id', budgetId)
    .maybeSingle();
  if (budgetError) throw new Error(budgetError.message);
  if (!budget) throw new Error('SHARED_BUDGET_NOT_FOUND');

  const { data: membership, error: memberError } = await sb
    .from('shared_budget_members')
    .select('*')
    .eq('budget_id', budgetId)
    .eq('user_id', userId)
    .maybeSingle();
  if (memberError) throw new Error(memberError.message);

  const ownerMembership = budget.owner_user_id === userId
    ? { role: 'OWNER', user_id: userId, budget_id: budgetId }
    : null;

  const effectiveMembership = membership || ownerMembership;
  if (!effectiveMembership) throw new Error('SHARED_BUDGET_ACCESS_DENIED');
  return { budget, membership: effectiveMembership };
};

export const canManageSharedBudget = (role: string) => ['OWNER', 'MANAGER'].includes(role.toUpperCase());
export const canSpendFromSharedBudget = (role: string) => ['OWNER', 'MANAGER', 'SPENDER'].includes(role.toUpperCase());
export const canReviewSharedBudgetSpend = (role: string) => ['OWNER', 'MANAGER'].includes(role.toUpperCase());

export const resolveUserBySharedBudgetIdentifier = async (sb: any, identifier: string) => {
  return resolveUserBySharedPotIdentifier(sb, identifier);
};

export const expireSharedBudgetInvitationIfNeeded = async (sb: any, invite: any) => {
  if (!invite?.expires_at) return invite;
  if (String(invite.status || '').toUpperCase() !== 'PENDING') return invite;
  if (new Date(invite.expires_at).getTime() > Date.now()) return invite;

  const { data, error } = await sb
    .from('shared_budget_invitations')
    .update({
      status: 'EXPIRED',
      updated_at: new Date().toISOString(),
    })
    .eq('id', invite.id)
    .select('*')
    .single();
  if (error) throw new Error(error.message);
  return data || invite;
};
