import { getAdminSupabase } from '../../backend/supabaseClient.js';

export const syncUserIdentityClassification = async (
  userId: string,
  updates: { role: string; registryType: string; metadata?: Record<string, any> },
) => {
  const adminSb = getAdminSupabase();
  if (!adminSb) throw new Error('DB_OFFLINE');

  const normalizedRole = String(updates.role).trim().toUpperCase();
  const normalizedRegistryType = String(updates.registryType).trim().toUpperCase();

  const { data: authUserResult, error: authUserError } = await adminSb.auth.admin.getUserById(userId);
  if (authUserError) throw new Error(authUserError.message);
  const currentMetadata = authUserResult?.user?.user_metadata || {};

  const { error: profileError } = await adminSb
    .from('users')
    .update({
      role: normalizedRole,
      registry_type: normalizedRegistryType,
    })
    .eq('id', userId);
  if (profileError) throw new Error(profileError.message);

  const { error: authUpdateError } = await adminSb.auth.admin.updateUserById(userId, {
    user_metadata: {
      ...currentMetadata,
      role: normalizedRole,
      registry_type: normalizedRegistryType,
      ...(updates.metadata || {}),
    },
  });
  if (authUpdateError) throw new Error(authUpdateError.message);

  if (normalizedRole === 'AGENT') {
    const { data: userRow } = await adminSb
      .from('users')
      .select('full_name')
      .eq('id', userId)
      .maybeSingle();

    await adminSb.from('agents').upsert({
      user_id: userId,
      display_name: userRow?.full_name || 'Agent',
      status: 'active',
      commission_enabled: true,
      metadata: updates.metadata || {},
    }, { onConflict: 'user_id' });
  }
};
